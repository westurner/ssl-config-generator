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

test('gnutls: falls back to GROUP-ALL if no curves map to GnuTLS tokens', () => {
  const out = gnutls(baseForm(), Object.assign({}, BASE_OUTPUT, { tlsCurves: ['someUnknownGroup'] }));
  assert.match(out, /\+GROUP-ALL/);
});
