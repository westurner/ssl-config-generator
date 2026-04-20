// Unit tests for the Python `ssl` module template.
import test from 'node:test';
import assert from 'node:assert/strict';
import python from '../src/js/helpers/python.js';

const BASE_OUTPUT = {
  header: 'generated 1970-01-01, Mozilla Guideline v6.0',
  link: 'https://example.invalid/#x',
  protocols: ['TLSv1.2', 'TLSv1.3'],
  ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256'],
  cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
  tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
  serverPreferredOrder: true,
  hstsMaxAge: 63072000,
};

const baseForm = (overrides = {}) => Object.assign({
  pq: 'hybrid',
  opensslVersion: '3.5.0',
  config: 'intermediate',
  hsts: false,
}, overrides);

test('python: emits an SSLContext with minimum_version / maximum_version', () => {
  const out = python(baseForm(), BASE_OUTPUT);
  assert.match(out, /^import ssl$/m);
  assert.match(out, /context = ssl\.SSLContext\(ssl\.PROTOCOL_TLS_SERVER\)/);
  assert.match(out, /context\.minimum_version = ssl\.TLSVersion\.TLSv1_2/);
  assert.match(out, /context\.maximum_version = ssl\.TLSVersion\.TLSv1_3/);
});

test('python: modern profile pins minimum_version = TLSv1_3', () => {
  const out = python(
    baseForm({ config: 'modern' }),
    Object.assign({}, BASE_OUTPUT, { protocols: ['TLSv1.3'] }),
  );
  assert.match(out, /context\.minimum_version = ssl\.TLSVersion\.TLSv1_3/);
  assert.match(out, /context\.maximum_version = ssl\.TLSVersion\.TLSv1_3/);
});

test('python: emits set_ciphers() with the OpenSSL TLSv1.2 cipher list (colon-joined)', () => {
  const out = python(baseForm(), BASE_OUTPUT);
  assert.match(
    out,
    /context\.set_ciphers\("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"\)/,
  );
});

test('python: emits set_groups() with the colon-joined group list and a set_ecdh_curve fallback', () => {
  const out = python(baseForm(), BASE_OUTPUT);
  assert.match(
    out,
    /context\.set_groups\("X25519MLKEM768:X25519:prime256v1:secp384r1"\)/,
  );
  // The single-curve fallback must skip ML-KEM hybrids (set_ecdh_curve
  // would reject them) and use the first classical curve.
  assert.match(out, /context\.set_ecdh_curve\("X25519"\)/);
});

test('python: PQ-only mode emits the "classical curves are intentionally omitted" comment', () => {
  const out = python(
    baseForm({ pq: 'only' }),
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519MLKEM768'] }),
  );
  assert.match(out, /PQ-only mode: classical curves are intentionally omitted/);
  assert.match(out, /context\.set_groups\("X25519MLKEM768"\)/);
  // No ML-KEM-only group in the list, so the fallback should not advertise
  // a hybrid group to set_ecdh_curve(); it must fall back to a classical
  // baseline curve (which is the documented behaviour).
  assert.match(out, /context\.set_ecdh_curve\("prime256v1"\)/);
});

test('python: hybrid mode includes the downgrade-risk comment', () => {
  const out = python(baseForm({ pq: 'hybrid' }), BASE_OUTPUT);
  assert.match(out, /downgrade/i);
});

test('python: warns when PQ mode is selected with OpenSSL < 3.5.0', () => {
  const out = python(baseForm({ opensslVersion: '3.4.0' }), BASE_OUTPUT);
  assert.match(out, /WARNING: built-in ML-KEM hybrid groups require OpenSSL 3\.5\.0/);
});

test('python: does not warn when PQ mode is "none"', () => {
  const out = python(
    baseForm({ pq: 'none', opensslVersion: '3.4.0' }),
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519', 'prime256v1', 'secp384r1'] }),
  );
  assert.doesNotMatch(out, /WARNING: built-in ML-KEM/);
});

test('python: HSTS comment is emitted only when form.hsts is true', () => {
  const without = python(baseForm({ hsts: false }), BASE_OUTPUT);
  assert.doesNotMatch(without, /Strict-Transport-Security/);
  const withHsts = python(baseForm({ hsts: true }), BASE_OUTPUT);
  assert.match(withHsts, /Strict-Transport-Security: max-age=63072000; includeSubDomains/);
});

test('python: serverPreferredOrder toggles SSL_OP_CIPHER_SERVER_PREFERENCE', () => {
  const on = python(baseForm(), BASE_OUTPUT);
  assert.match(on, /context\.options \|= ssl\.OP_CIPHER_SERVER_PREFERENCE/);
  const off = python(
    baseForm(),
    Object.assign({}, BASE_OUTPUT, { serverPreferredOrder: false }),
  );
  assert.doesNotMatch(off, /OP_CIPHER_SERVER_PREFERENCE/);
});

test('python: notes that TLSv1.3 ciphersuites come from openssl.cnf, not from Python', () => {
  const out = python(baseForm(), BASE_OUTPUT);
  assert.match(out, /TLSv1\.3 ciphersuites are NOT exposed by Python/);
  assert.match(out, /openssl\.cnf/);
});
