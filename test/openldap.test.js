// openldap helper — generic-suite tests via the shared harness plus
// OpenLDAP-specific assertions for the TLSProtocolMin numbering, the
// TLSECName curve list, and the PQ-aware codepath.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runStandardHelperSuite } from './_helpers/harness.js';
import { makeForm, makeOutput, PQ_MODES } from './_helpers/fixtures.js';
import openldap from '../src/js/helpers/openldap.js';

runStandardHelperSuite({
  name: 'openldap',
  helper: openldap,
  serverVersion: '2.6.9',
  cipherFormat: 'openssl',
  supportsHsts: false,
  supportsPq: true,
  // OpenLDAP's TLSProtocolMin uses on-the-wire numbering: 3.1=TLS 1.0,
  // 3.3=TLS 1.2, 3.4=TLS 1.3. Anchor the regex on a trailing space or
  // newline so 3.3 doesn't accidentally match 3.4 (or vice versa).
  protocolDirective: {
    modern:       /^TLSProtocolMin 3\.4(\s|$)/m,
    intermediate: /^TLSProtocolMin 3\.3(\s|$)/m,
    old:          /^TLSProtocolMin 3\.1(\s|$)/m,
  },
});

// ---------------------------------------------------------------------------
// OpenLDAP-specific assertions.
// ---------------------------------------------------------------------------

test('openldap: emits TLSCertificate / TLSCertificateKey / TLSCACertificate paths', () => {
  const out = openldap(makeForm(), makeOutput('intermediate'));
  assert.match(out, /^TLSCertificateFile\s+\/path\/to\/signed_cert_plus_intermediates$/m);
  assert.match(out, /^TLSCertificateKeyFile\s+\/path\/to\/private_key$/m);
  assert.match(out, /^TLSCACertificateFile\s+\/path\/to\/ca_certs$/m);
});

test('openldap: TLSCipherSuite uses OpenSSL cipher syntax (colon-joined)', () => {
  const out = openldap(makeForm(), makeOutput('intermediate'));
  assert.match(
    out,
    /^TLSCipherSuite\s+ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256/m,
  );
});

test('openldap: TLSECName is a colon-separated group list (single line)', () => {
  const out = openldap(
    makeForm({ pq: 'hybrid' }),
    makeOutput('intermediate', {
      tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
    }),
  );
  assert.match(out, /^TLSECName X25519MLKEM768:X25519:prime256v1:secp384r1$/m);
});

test('openldap: documents the OpenLDAP 2.5+ requirement for the multi-curve list', () => {
  const out = openldap(makeForm(), makeOutput('intermediate'));
  assert.match(out, /OpenLDAP 2\.5\+/);
});

test('openldap: notes that TLSv1.3 ciphersuites come from openssl.cnf, not slapd', () => {
  const out = openldap(makeForm(), makeOutput('intermediate'));
  assert.match(out, /TLSv1\.3 ciphersuites are not configurable here/);
  assert.match(out, /openssl\.cnf/);
});

test('openldap: legacy "old" profile maps TLSv1 floor to TLSProtocolMin 3.1', () => {
  // state.js emits the legacy floor as 'TLSv1' (not 'TLSv1.0'); the helper
  // must accept both spellings and produce the same 3.1 numbering.
  const outV1   = openldap(makeForm({ config: 'old' }),
    makeOutput('old', { protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] }));
  const outV1_0 = openldap(makeForm({ config: 'old' }),
    makeOutput('old', { protocols: ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] }));
  assert.match(outV1,   /^TLSProtocolMin 3\.1\s/m);
  assert.match(outV1_0, /^TLSProtocolMin 3\.1\s/m);
});

test('openldap: emits TLSDHParamFile only when usesDhe is true', () => {
  const withDhe = openldap(
    makeForm(),
    makeOutput('intermediate', { usesDhe: true,
      dhCommand: 'curl https://example.invalid/ffdhe2048.txt' }),
  );
  assert.match(withDhe, /^TLSDHParamFile\s+\/path\/to\/dhparam$/m);
  assert.match(withDhe, /ffdhe2048\.txt/);

  const without = openldap(
    makeForm(),
    makeOutput('intermediate', { usesDhe: false }),
  );
  assert.doesNotMatch(without, /TLSDHParamFile/);
});

test('openldap: PQ-mode comments are emitted only when form.pq !== "none"', () => {
  for (const mode of PQ_MODES) {
    const out = openldap(
      makeForm({ pq: mode }),
      makeOutput('intermediate', {
        tlsCurves: mode === 'only'
          ? ['X25519MLKEM768']
          : ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
      }),
    );
    if (mode === 'none') {
      assert.doesNotMatch(out, /Post-quantum:/);
      assert.doesNotMatch(out, /classical curves are intentionally omitted/);
    }
    else {
      assert.match(out, /Post-quantum:/, `pq=${mode} should mention PQ`);
    }
    if (mode === 'only') {
      assert.match(out, /classical curves are intentionally omitted/);
      // PQ-only must explicitly call out the TLS 1.3 floor requirement.
      assert.match(out, /TLSProtocolMin is pinned to 3\.4/);
    }
    if (mode === 'hybrid') {
      assert.match(out, /Hybrid PQ mode/);
    }
  }
});

test('openldap: warns when PQ mode is selected with OpenSSL < 3.5.0', () => {
  const out = openldap(
    makeForm({ pq: 'hybrid', opensslVersion: '3.4.0' }),
    makeOutput('intermediate', {
      tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
    }),
  );
  assert.match(out, /WARNING: built-in ML-KEM hybrid groups require OpenSSL 3\.5\.0/);
});

test('openldap: does NOT warn about OpenSSL < 3.5.0 when PQ mode is "none"', () => {
  const out = openldap(
    makeForm({ pq: 'none', opensslVersion: '3.4.0' }),
    makeOutput('intermediate', { tlsCurves: ['X25519', 'prime256v1', 'secp384r1'] }),
  );
  assert.doesNotMatch(out, /WARNING: built-in ML-KEM/);
});

test('openldap: header / fragment-link comments appear at the top', () => {
  const out = openldap(
    makeForm(),
    makeOutput('intermediate', {
      header: 'generated 2099-12-31, Mozilla Guideline v6.0',
      link:   'https://example.invalid/#openldap',
    }),
  );
  assert.match(out, /^# generated 2099-12-31, Mozilla Guideline v6\.0$/m);
  assert.match(out, /^# https:\/\/example\.invalid\/#openldap$/m);
});
