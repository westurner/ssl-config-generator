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
