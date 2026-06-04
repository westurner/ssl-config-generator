// Unit tests for the openssl.cnf snippet generator (src/js/helpers/opensslcnf.js).
// Run via `npm test` (uses @babel/register so we can `import` the helper).
import test from 'node:test';
import assert from 'node:assert/strict';
import opensslcnf from '../src/js/helpers/opensslcnf.js';

const BASE_OUTPUT = {
  header: 'generated 1970-01-01, Mozilla Guideline v6.0',
  link: 'https://example.invalid/#x',
  protocols: ['TLSv1.2', 'TLSv1.3'],
  ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256'],
  cipherSuites: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'],
  tlsCurves: ['X25519MLKEM768', 'X25519', 'prime256v1', 'secp384r1'],
  serverPreferredOrder: true,
};

const baseForm = (overrides = {}) => Object.assign({
  pq: 'hybrid',
  opensslVersion: '3.5.0',
  config: 'intermediate',
}, overrides);

test('opensslcnf: emits the standard openssl_init / ssl_module / system_default_sect layout', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /^openssl_conf = openssl_init$/m);
  assert.match(out, /^\[openssl_init\]$/m);
  assert.match(out, /^ssl_conf = ssl_module$/m);
  assert.match(out, /^\[ssl_module\]$/m);
  assert.match(out, /^system_default = system_default_sect$/m);
  assert.match(out, /^\[system_default_sect\]$/m);
});

test('opensslcnf: MinProtocol/MaxProtocol mirror output.protocols', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /^MinProtocol = TLSv1\.2$/m);
  assert.match(out, /^MaxProtocol = TLSv1\.3$/m);
});

test('opensslcnf: MinProtocol = TLSv1.3 for the modern profile', () => {
  const out = opensslcnf(
    baseForm({ config: 'modern' }),
    Object.assign({}, BASE_OUTPUT, { protocols: ['TLSv1.3'] }),
  );
  assert.match(out, /^MinProtocol = TLSv1\.3$/m);
  assert.match(out, /^MaxProtocol = TLSv1\.3$/m);
});

test('opensslcnf: emits Groups and Ciphersuites lines with colon separators', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /^Groups = X25519MLKEM768:X25519:prime256v1:secp384r1$/m);
  assert.match(out, /^Ciphersuites = TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384$/m);
  assert.match(out, /^CipherString = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256$/m);
});

test('opensslcnf: hybrid mode includes the downgrade-risk comment', () => {
  const out = opensslcnf(baseForm({ pq: 'hybrid' }), BASE_OUTPUT);
  assert.match(out, /downgrade/i);
});

test('opensslcnf: PQ-only mode forces MinProtocol = TLSv1.3 even for intermediate profile', () => {
  // state.js filters protocols to ['TLSv1.3'] when pqMode === 'only';
  // verify that this results in MinProtocol = TLSv1.3 (not TLSv1.2).
  const out = opensslcnf(
    baseForm({ pq: 'only' }),
    Object.assign({}, BASE_OUTPUT, { protocols: ['TLSv1.3'], tlsCurves: ['X25519MLKEM768'] }),
  );
  assert.match(out, /^MinProtocol = TLSv1\.3$/m);
  assert.doesNotMatch(out, /^MinProtocol = TLSv1\.2$/m);
});

test('opensslcnf: PQ-only mode includes the "classical curves omitted" comment', () => {
  const out = opensslcnf(
    baseForm({ pq: 'only' }),
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519MLKEM768'] }),
  );
  assert.match(out, /PQ-only mode/i);
  assert.match(out, /^Groups = X25519MLKEM768$/m);
});

test('opensslcnf: Non-PQ mode does not emit a hybrid/PQ-only comment block', () => {
  const out = opensslcnf(
    baseForm({ pq: 'none' }),
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519', 'prime256v1', 'secp384r1'] }),
  );
  assert.doesNotMatch(out, /Hybrid PQ mode/);
  assert.doesNotMatch(out, /PQ-only mode: classical curves are intentionally omitted/);
  assert.match(out, /^Groups = X25519:prime256v1:secp384r1$/m);
});

test('opensslcnf: warns when PQ mode is selected with OpenSSL < 3.5.0', () => {
  const out = opensslcnf(
    baseForm({ pq: 'hybrid', opensslVersion: '3.0.0' }),
    BASE_OUTPUT,
  );
  assert.match(out, /WARNING: built-in ML-KEM hybrid groups/);
});

test('opensslcnf: does NOT warn when PQ mode is "none"', () => {
  const out = opensslcnf(
    baseForm({ pq: 'none', opensslVersion: '3.0.0' }),
    BASE_OUTPUT,
  );
  assert.doesNotMatch(out, /WARNING: built-in ML-KEM/);
});

test('opensslcnf: emits Options = ServerPreference when serverPreferredOrder is set', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /^Options = ServerPreference$/m);
});

test('opensslcnf: header documents that openssl.cnf does NOT apply to rustls', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /rustls/);
});

test('opensslcnf: header explains that MinProtocol mirrors the chosen profile', () => {
  const out = opensslcnf(baseForm(), BASE_OUTPUT);
  assert.match(out, /modern.*TLSv1\.3/);
  assert.match(out, /intermediate.*TLSv1\.2/);
});
