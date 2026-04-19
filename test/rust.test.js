// Unit tests for the rustls (Rust) template.
import test from 'node:test';
import assert from 'node:assert/strict';
import rust from '../src/js/helpers/rust.js';

const BASE_OUTPUT = {
  header: 'generated 1970-01-01, Mozilla Guideline v6.0',
  link: 'https://example.invalid/#x',
  protocols: ['TLSv1.2', 'TLSv1.3'],
  ciphers: [],
  cipherSuites: [],
  tlsCurves: ['X25519MLKEM768', 'X25519'],
  serverPreferredOrder: true,
  hstsMaxAge: 63072000,
};

const baseForm = (overrides = {}) => Object.assign({
  pq: 'hybrid',
  config: 'intermediate',
  hsts: false,
}, overrides);

test('rust: emits a rustls ServerConfig with TLS1.2 + TLS1.3 versions', () => {
  const out = rust(baseForm(), BASE_OUTPUT);
  assert.match(out, /use rustls::\{ServerConfig, version\};/);
  assert.match(out, /&version::TLS13,/);
  assert.match(out, /&version::TLS12,/);
});

test('rust: omits TLS1.2 from the version list when only TLS1.3 is selected', () => {
  const out = rust(baseForm(), Object.assign({}, BASE_OUTPUT, { protocols: ['TLSv1.3'] }));
  assert.match(out, /&version::TLS13,/);
  assert.doesNotMatch(out, /&version::TLS12,/);
});

test('rust: HSTS comment is emitted only when form.hsts is true', () => {
  const without = rust(baseForm({ hsts: false }), BASE_OUTPUT);
  assert.doesNotMatch(without, /Strict-Transport-Security/);
  const withHsts = rust(baseForm({ hsts: true }), BASE_OUTPUT);
  assert.match(withHsts, /Strict-Transport-Security: max-age=63072000/);
});

test('rust: header documents that rustls negotiates X25519MLKEM768 automatically', () => {
  const out = rust(baseForm(), BASE_OUTPUT);
  assert.match(out, /X25519MLKEM768/);
  assert.match(out, /aws-lc-rs/);
});
