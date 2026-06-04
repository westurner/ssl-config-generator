// Unit tests for the GnuTLS priority-string template.
import test from 'node:test';
import assert from 'node:assert/strict';
import gnutls from '../src/js/helpers/gnutls.js';

const BASE_OUTPUT = {
  header: 'generated 1970-01-01, Mozilla Guideline v6.0',
  link: 'https://example.invalid/#x',
  protocols: ['TLSv1.2', 'TLSv1.3'],
  ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256'],
  cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
  tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
  serverPreferredOrder: true,
};

const baseForm = (overrides = {}) => Object.assign({
  pq: 'hybrid',
  serverVersion: '3.8.10',
  config: 'intermediate',
}, overrides);

test('gnutls: emits a NONE-rooted priority string with PQ group token', () => {
  const out = gnutls(baseForm(), BASE_OUTPUT);
  assert.match(out, /\nNONE:.*\+GROUP-X25519-MLKEM768/);
  assert.match(out, /\+VERS-TLS1\.3/);
  assert.match(out, /\+VERS-TLS1\.2/);
  assert.match(out, /%SERVER_PRECEDENCE/);
});

test('gnutls: warns when PQ mode is selected with GnuTLS < 3.8.10', () => {
  const out = gnutls(baseForm({ serverVersion: '3.8.0' }), BASE_OUTPUT);
  assert.match(out, /requires GnuTLS 3\.8\.10/);
});

test('gnutls: does not warn when PQ mode is "none"', () => {
  const out = gnutls(
    baseForm({ pq: 'none', serverVersion: '3.8.0' }),
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519', 'prime256v1', 'secp384r1'] }),
  );
  assert.doesNotMatch(out, /requires GnuTLS/);
  assert.doesNotMatch(out, /\+GROUP-X25519-MLKEM768/);
});

test('gnutls: omits %SERVER_PRECEDENCE when serverPreferredOrder is false', () => {
  // Covers the else branch of `if (output.serverPreferredOrder)`.
  const out = gnutls(
    baseForm({ pq: 'none' }),
    Object.assign({}, BASE_OUTPUT, { serverPreferredOrder: false, tlsCurves: ['X25519', 'prime256v1'] }),
  );
  assert.doesNotMatch(out, /%SERVER_PRECEDENCE/);
});

test('gnutls: emits the +AES-128-CBC / +3DES-CBC legacy tail for the old profile', () => {
  // Covers the `if (form.config === 'old')` branch of the cipher-token block.
  const out = gnutls(baseForm({ config: 'old', pq: 'none' }), Object.assign({}, BASE_OUTPUT, {
    protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
    tlsCurves: ['X25519', 'prime256v1', 'secp384r1'],
  }));
  assert.match(out, /\+AES-128-CBC/);
  assert.match(out, /\+3DES-CBC/);
});

test('gnutls: warns and falls back to the Mozilla classical-group baseline when no curves map (NOT GROUP-ALL — that would silently widen the policy)', () => {
  const out = gnutls(baseForm(), Object.assign({}, BASE_OUTPUT, { tlsCurves: ['someUnknownGroup'] }));
  // The unsafe `+GROUP-ALL` must NOT appear: it would enable every group
  // GnuTLS knows, including weaker DH groups deliberately excluded by the
  // Mozilla profile.
  assert.doesNotMatch(out, /\+GROUP-ALL\b/);
  // A WARNING comment must name the unrecognized group(s) so the operator
  // sees the silent narrowing/widening decision before deploying.
  assert.match(out, /# WARNING: none of the requested TLS groups \(someUnknownGroup\)/);
  // The fallback uses the Mozilla classical-group baseline, not whatever
  // happens to be compiled into the local libgnutls.
  assert.match(out, /\+GROUP-X25519\b/);
  assert.match(out, /\+GROUP-SECP256R1\b/);
  assert.match(out, /\+GROUP-SECP384R1\b/);
});

test('gnutls: warns about partially unmapped curves and silently drops only the unrecognized ones', () => {
  // Mix mappable + unmappable groups — the helper should keep the mappable
  // ones, drop the unmappable ones, AND emit a WARNING naming the dropped
  // entries so the operator notices the silent narrowing.
  const out = gnutls(baseForm(), Object.assign({}, BASE_OUTPUT, {
    tlsCurves: ['X25519', 'someBogusGroup', 'anotherBogusGroup'],
  }));
  assert.match(out, /\+GROUP-X25519\b/);
  assert.doesNotMatch(out, /\+GROUP-ALL\b/);
  // The unrecognized group names must appear ONLY inside the WARNING comment
  // block, never as a `+someBogusGroup` token in the priority string.
  assert.doesNotMatch(out, /\+someBogusGroup\b/);
  assert.doesNotMatch(out, /\+anotherBogusGroup\b/);
  assert.match(out, /# WARNING: the following requested TLS groups[\s\S]+someBogusGroup, anotherBogusGroup/);
});
