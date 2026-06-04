// Unit tests for the s2n-tls (C library) template.
import test from 'node:test';
import assert from 'node:assert/strict';
import s2n from '../src/js/helpers/s2n.js';

const BASE_OUTPUT = {
  header: 'generated 1970-01-01, Mozilla Guideline v6.0',
  link: 'https://example.invalid/#x',
  protocols: ['TLSv1.2', 'TLSv1.3'],
  ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256'],
  cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
  tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
  serverPreferredOrder: true,
  hstsMaxAge: 63072000,
};

const baseForm = (overrides = {}) => Object.assign({
  pq: 'none',
  serverVersion: '1.7.2',
  config: 'intermediate',
  hsts: false,
  ocsp: false,
}, overrides);

test('s2n: emits a self-contained C snippet that builds an s2n_config', () => {
  const out = s2n(baseForm(), BASE_OUTPUT);
  assert.match(out, /#include <s2n\.h>/);
  assert.match(out, /s2n_init\(\)/);
  assert.match(out, /s2n_config_new\(\)/);
  assert.match(out, /s2n_config_add_cert_chain_and_key_to_store\(/);
  assert.match(out, /s2n_config_set_cipher_preferences\(config, "/);
  assert.match(out, /s2n_config_free\(config\);/);
  assert.match(out, /s2n_cleanup\(\);/);
});

test('s2n: maps each Mozilla profile to the expected named security policy', () => {
  const modern = s2n(baseForm({ config: 'modern' }), BASE_OUTPUT);
  assert.match(modern, /s2n_config_set_cipher_preferences\(config, "default_tls13"\)/);

  const intermediate = s2n(baseForm({ config: 'intermediate' }), BASE_OUTPUT);
  assert.match(intermediate, /s2n_config_set_cipher_preferences\(config, "default"\)/);

  const old = s2n(baseForm({ config: 'old' }), BASE_OUTPUT);
  assert.match(old, /s2n_config_set_cipher_preferences\(config, "20190214"\)/);
  assert.match(old, /steadily removing legacy security policies/);
});

test('s2n: PQ "hybrid" or "only" overrides the policy with default_pq', () => {
  const hybrid = s2n(baseForm({ pq: 'hybrid', config: 'modern' }), BASE_OUTPUT);
  assert.match(hybrid, /s2n_config_set_cipher_preferences\(config, "default_pq"\)/);
  assert.doesNotMatch(hybrid, /s2n_config_set_cipher_preferences\(config, "default_tls13"\)/);

  const only = s2n(baseForm({ pq: 'only', config: 'intermediate' }), BASE_OUTPUT);
  assert.match(only, /s2n_config_set_cipher_preferences\(config, "default_pq"\)/);
  assert.match(only, /does not currently expose a stable "PQ only" named/);

  const none = s2n(baseForm({ pq: 'none' }), BASE_OUTPUT);
  assert.doesNotMatch(none, /default_pq/);
});

test('s2n: warns when PQ mode is selected with s2n-tls < 1.5.0', () => {
  const out = s2n(baseForm({ pq: 'hybrid', serverVersion: '1.4.0' }), BASE_OUTPUT);
  assert.match(out, /requires s2n-tls 1\.5\.0/);
});

test('s2n: emits s2n_config_set_status_request_type only when form.ocsp is true', () => {
  const without = s2n(baseForm({ ocsp: false }), BASE_OUTPUT);
  assert.doesNotMatch(without, /s2n_config_set_status_request_type/);
  const withOcsp = s2n(baseForm({ ocsp: true }), BASE_OUTPUT);
  assert.match(withOcsp, /s2n_config_set_status_request_type\(config, S2N_STATUS_REQUEST_OCSP\)/);
});

test('s2n: HSTS reminder comment is emitted only when form.hsts is true', () => {
  const without = s2n(baseForm({ hsts: false }), BASE_OUTPUT);
  assert.doesNotMatch(without, /Strict-Transport-Security/);
  const withHsts = s2n(baseForm({ hsts: true }), BASE_OUTPUT);
  assert.match(withHsts, /Strict-Transport-Security: max-age=63072000/);
});

test('s2n: does not pick a TLS-1.3-only policy when TLS 1.3 is not in protocols', () => {
  const out = s2n(
    baseForm({ config: 'modern' }),
    Object.assign({}, BASE_OUTPUT, { protocols: ['TLSv1.2'] }),
  );
  assert.doesNotMatch(out, /"default_tls13"/);
  assert.match(out, /s2n_config_set_cipher_preferences\(config, "default"\)/);
});

// ---------------------------------------------------------------------------
// Cryptographic-correctness / hardening tests.
//
// These tests treat the rendered C snippet as a security artefact: the
// generator must not silently emit weak primitives, must preserve the
// provenance header so an auditor can trace the snippet back to a
// guideline version, and must produce byte-identical output for the same
// inputs (so reviewers can diff two runs).
// ---------------------------------------------------------------------------

test('s2n: preserves the Mozilla guideline header + link for auditability', () => {
  const out = s2n(baseForm(), BASE_OUTPUT);
  assert.match(out, /generated 1970-01-01, Mozilla Guideline v6\.0/);
  assert.match(out, /https:\/\/example\.invalid\/#x/);
});

test('s2n: every {profile} x {pq} combination resolves to a known policy', () => {
  // The full combinatorial matrix; this guards against future refactors
  // accidentally dropping a branch and emitting `"undefined"` as the
  // policy name (which s2n would reject at runtime with
  // S2N_ERR_INVALID_SECURITY_POLICY).
  const KNOWN = new Set(['default', 'default_tls13', 'default_pq', '20190214']);
  const setCall = /s2n_config_set_cipher_preferences\(config, "([^"]+)"\)/;
  for (const config of ['modern', 'intermediate', 'old']) {
    for (const pq of ['none', 'hybrid', 'only']) {
      const out = s2n(baseForm({ config, pq }), BASE_OUTPUT);
      const m = out.match(setCall);
      assert.ok(m, `no policy call for ${config}/${pq}`);
      assert.ok(KNOWN.has(m[1]),
        `unexpected policy "${m[1]}" for ${config}/${pq}`);
      assert.doesNotMatch(out, /"undefined"/);
      assert.doesNotMatch(out, /"null"/);
    }
  }
});

test('s2n: PQ-only mode surfaces an explicit classical-fallback caveat', () => {
  // s2n's "default_pq" still permits classical key exchange. A user who
  // selected "PQ only" is asking for a hard guarantee; we must NOT silently
  // give them a hybrid-with-fallback policy without a clear warning.
  const out = s2n(baseForm({ pq: 'only' }), BASE_OUTPUT);
  assert.match(out, /"default_pq"/);
  assert.match(out, /classical fallback/i);
  assert.match(out, /best-effort PQ/i);
});

test('s2n: rendered C never references known-broken primitives', () => {
  // Defence-in-depth: regardless of profile / PQ mode, the emitted C code
  // must not mention RC4, MD5, EXPORT-grade, NULL ciphers, SSLv2/SSLv3,
  // or the s2n knob that turns TLS 1.3 off (`s2n_disable_tls13_in_test`).
  const FORBIDDEN = [
    /\bRC4\b/, /\bMD5\b/, /\bEXPORT\b/, /\bNULL-(MD5|SHA)\b/,
    /\bSSLv2\b/, /\bSSLv3\b/, /s2n_disable_tls13/,
  ];
  for (const config of ['modern', 'intermediate', 'old']) {
    for (const pq of ['none', 'hybrid', 'only']) {
      const out = s2n(baseForm({ config, pq, ocsp: true, hsts: true }), BASE_OUTPUT);
      for (const re of FORBIDDEN) {
        assert.doesNotMatch(out, re,
          `forbidden token ${re} appeared for ${config}/${pq}`);
      }
    }
  }
});

test('s2n: cipher / ciphersuite lists are only rendered as C comments', () => {
  // s2n is configured by named policies, so output.ciphers /
  // output.cipherSuites must NEVER appear as executable C (e.g. as a
  // string literal passed to s2n_config_set_cipher_preferences); they may
  // only appear inside the `/* ... */` informational block that precedes
  // the `#include <stdio.h>` line.
  const OUT = Object.assign({}, BASE_OUTPUT, {
    ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256'],
    cipherSuites: ['TLS_AES_128_GCM_SHA256'],
  });
  const out = s2n(baseForm(), OUT);
  const codeStart = out.indexOf('#include <stdio.h>');
  assert.ok(codeStart > 0, 'expected the C code section to begin with #include <stdio.h>');
  const code = out.slice(codeStart);
  assert.doesNotMatch(code, /ECDHE-ECDSA-AES128-GCM-SHA256/);
  assert.doesNotMatch(code, /TLS_AES_128_GCM_SHA256/);
  // And confirm the names DID appear in the comment header (otherwise we
  // would have lost the informational listing entirely).
  assert.match(out.slice(0, codeStart), /TLS_AES_128_GCM_SHA256/);
});

test('s2n: every error path that follows s2n_config_new frees and cleans up', () => {
  // Resource-leak hygiene: any `return EXIT_FAILURE` that appears AFTER
  // the s2n_config_new() NULL check must be immediately preceded (within
  // the same block) by `s2n_config_free(config)` and `s2n_cleanup()`.
  // Pre-allocation failures (s2n_init, s2n_config_new) are exempt because
  // there is nothing to free yet. The success-path return must also free.
  const out = s2n(baseForm({ ocsp: true }), BASE_OUTPUT);
  // Split the body at the s2n_config_new() NULL check: anything after it
  // owns `config` and must clean up on every exit.
  const ownStart = out.indexOf('s2n_config_add_cert_chain_and_key_to_store');
  assert.ok(ownStart > 0);
  const ownsConfig = out.slice(ownStart);
  // Every return statement in the owns-config region must be preceded by
  // a free + cleanup pair within the prior 200 chars.
  const returnRe = /return EXIT_(?:FAILURE|SUCCESS);/g;
  let m;
  while ((m = returnRe.exec(ownsConfig)) !== null) {
    const window = ownsConfig.slice(Math.max(0, m.index - 200), m.index);
    assert.match(window, /s2n_config_free\(config\);/,
      `return at offset ${m.index} not preceded by s2n_config_free`);
    assert.match(window, /s2n_cleanup\(\);/,
      `return at offset ${m.index} not preceded by s2n_cleanup`);
  }
  // And every `s2n_config_free(config)` must be immediately followed by
  // a `s2n_cleanup()` (i.e. the pair is never split, preventing
  // free-without-global-shutdown bugs).
  const pairs = ownsConfig.match(/s2n_config_free\(config\);\s*\n\s*s2n_cleanup\(\);/g) || [];
  const frees = ownsConfig.match(/s2n_config_free\(config\);/g) || [];
  assert.equal(pairs.length, frees.length,
    'every s2n_config_free must be immediately followed by s2n_cleanup');
});

test('s2n: output is deterministic for identical inputs', () => {
  // Reviewers must be able to re-run the generator and diff against a
  // previous render; any source of nondeterminism (Date.now, Math.random,
  // unstable iteration order) would defeat that. The header timestamp is
  // injected via output.header by the caller, so the helper itself must
  // be a pure function of (form, output).
  const a = s2n(baseForm({ pq: 'hybrid', ocsp: true, hsts: true }), BASE_OUTPUT);
  const b = s2n(baseForm({ pq: 'hybrid', ocsp: true, hsts: true }), BASE_OUTPUT);
  assert.equal(a, b);
});

test('s2n: unknown form.config falls back to a known policy, not undefined', () => {
  // Defence against a future UI change introducing a 4th profile name
  // before the helper is updated.
  const out = s2n(baseForm({ config: 'experimental' }), BASE_OUTPUT);
  assert.doesNotMatch(out, /"undefined"/);
  assert.match(out, /s2n_config_set_cipher_preferences\(config, "default"\)/);
});

test('s2n: OCSP + HSTS + PQ can be enabled simultaneously', () => {
  // Composite test: ensure none of the conditional blocks shadow each
  // other when all three flags are on.
  const out = s2n(
    baseForm({ pq: 'hybrid', ocsp: true, hsts: true, config: 'modern' }),
    BASE_OUTPUT,
  );
  assert.match(out, /s2n_config_set_cipher_preferences\(config, "default_pq"\)/);
  assert.match(out, /s2n_config_set_status_request_type\(config, S2N_STATUS_REQUEST_OCSP\)/);
  assert.match(out, /Strict-Transport-Security: max-age=63072000/);
});

test('s2n: warns that "old" profile + PQ are mutually exclusive', () => {
  // ML-KEM is a TLS 1.3 group; the "old" profile targets pre-TLS-1.2
  // clients. Selecting both is a contradiction the user must resolve, so
  // the rendered C must surface a clear warning in either PQ mode.
  for (const pq of ['hybrid', 'only']) {
    const out = s2n(baseForm({ config: 'old', pq }), BASE_OUTPUT);
    assert.match(out, /mutually exclusive/i,
      `expected "old" + pq=${pq} to warn about mutual exclusivity`);
    assert.match(out, /ML-KEM is a TLS 1\.3 group/);
    assert.match(out, /Choose either backwards-compatibility/i);
  }
});

test('s2n: does NOT emit the old+PQ warning when only one of them is set', () => {
  // Negative cases: warning must not fire for old-without-PQ or for
  // PQ-without-old, otherwise we would be crying wolf.
  const oldNoPq = s2n(baseForm({ config: 'old', pq: 'none' }), BASE_OUTPUT);
  assert.doesNotMatch(oldNoPq, /mutually exclusive/i);

  for (const config of ['modern', 'intermediate']) {
    const pqNoOld = s2n(baseForm({ config, pq: 'hybrid' }), BASE_OUTPUT);
    assert.doesNotMatch(pqNoOld, /mutually exclusive/i,
      `unexpected mutual-exclusivity warning for ${config}+pq`);
  }
});
