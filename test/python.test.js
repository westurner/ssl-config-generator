// Unit tests for the Python `ssl` module template.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
    Object.assign({}, BASE_OUTPUT, { tlsCurves: ['X25519MLKEM768'], protocols: ['TLSv1.3'] }),
  );
  assert.match(out, /PQ-only mode: classical curves are intentionally omitted/);
  assert.match(out, /context\.set_groups\("X25519MLKEM768"\)/);
  // PQ-only mode must NOT silently fall back to a classical single curve on
  // Python < 3.13 — set_ecdh_curve() rejects ML-KEM names, so calling it
  // with a classical curve here would defeat the user's PQ-only choice.
  // The helper must raise loudly instead. (Match the function CALL, not
  // any explanatory comment that names set_ecdh_curve.)
  assert.doesNotMatch(out, /context\.set_ecdh_curve\(/);
  assert.match(out, /raise RuntimeError\(/);
  assert.match(out, /PQ-only mode requires Python >= 3\.13/);
});

test('python: PQ-only mode defensively pins minimum_version=TLSv1_3 even if protocols[0] is lower', () => {
  // Even if state.js's protocol override were ever bypassed (or a caller
  // constructed `output` directly), python.js must independently enforce
  // the TLSv1.3 floor when pq=='only'. ML-KEM key_share is TLS 1.3-only.
  const out = python(
    baseForm({ pq: 'only' }),
    Object.assign({}, BASE_OUTPUT, {
      tlsCurves: ['X25519MLKEM768'],
      protocols: ['TLSv1.2', 'TLSv1.3'],   // intentionally NOT just ['TLSv1.3']
    }),
  );
  assert.match(out, /context\.minimum_version = ssl\.TLSVersion\.TLSv1_3/);
});

test('python: hybrid mode keeps the classical-curve fallback for Python < 3.13', () => {
  // pq='hybrid' explicitly accepts a classical TLS 1.2 fallback, so the
  // single-curve fallback for Python < 3.13 is documented behaviour
  // (NOT a silent downgrade — the user already opted in to interop).
  const out = python(baseForm({ pq: 'hybrid' }), BASE_OUTPUT);
  assert.match(out, /context\.set_ecdh_curve\("X25519"\)/);
  assert.doesNotMatch(out, /raise RuntimeError\(/);
});

test('python: notes that ML-KEM groups are TLS 1.3-only (key_share extension)', () => {
  const out = python(baseForm({ pq: 'hybrid' }), BASE_OUTPUT);
  assert.match(out, /TLS 1\.3-only/);
  assert.match(out, /key_share/);
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

// ---------------------------------------------------------------------------
// End-to-end: the rendered template must be syntactically valid Python.
//
// Probe for `python3` once at module load. The end-to-end tests below are
// silently skipped when python3 is not on PATH (mirrors the `pwsh`-skip
// pattern in test/iis.test.js): they do NOT replace the regex assertions
// above, they supplement them with a real-Python AST parse when available.
//
// We use `ast.parse()` (not `compile()` / not `exec()`) so the test is
// purely a syntactic check — no socket is opened, no SSLContext is built,
// and the `pq=='only'` render's `raise RuntimeError(...)` parses fine even
// though it would raise at runtime on Python < 3.13.
// ---------------------------------------------------------------------------
const PYTHON3 = (() => {
  try {
    const r = spawnSync('python3', ['-c', 'import sys, ast'], {
      encoding: 'utf8', timeout: 10000,
    });
    return r.status === 0 ? 'python3' : null;
  } catch { return null; }
})();

const PY_SKIP_REASON = 'python3 not available on PATH';

// Pipe the rendered Python through `python3 -c "import sys, ast;
// ast.parse(sys.stdin.read())"`. Returns the spawnSync result so the caller
// can inspect status / stderr.
function astParse(rendered) {
  return spawnSync(
    PYTHON3,
    ['-c', 'import sys, ast; ast.parse(sys.stdin.read())'],
    { input: rendered, encoding: 'utf8', timeout: 15000 },
  );
}

test('python: rendered template parses with ast.parse() — pq=hybrid + intermediate profile',
  { skip: PYTHON3 ? false : PY_SKIP_REASON }, () => {
    const out = python(baseForm({ pq: 'hybrid', hsts: true }), BASE_OUTPUT);
    const r = astParse(out);
    assert.equal(r.status, 0,
      `ast.parse failed (exit ${r.status}):\nSTDERR:\n${r.stderr}\n--- rendered ---\n${out}`);
  });

test('python: rendered template parses with ast.parse() — pq=only + modern profile',
  { skip: PYTHON3 ? false : PY_SKIP_REASON }, () => {
    // pq='only' takes the `raise RuntimeError(...)` branch in the
    // `except AttributeError:` fallback. ast.parse is purely syntactic,
    // so the raise statement parses cleanly even on Python < 3.13.
    const out = python(
      baseForm({ pq: 'only', config: 'modern' }),
      Object.assign({}, BASE_OUTPUT, {
        protocols: ['TLSv1.3'],
        tlsCurves: ['X25519MLKEM768'],
      }),
    );
    const r = astParse(out);
    assert.equal(r.status, 0,
      `ast.parse failed (exit ${r.status}):\nSTDERR:\n${r.stderr}\n--- rendered ---\n${out}`);
  });

test('python: rendered template parses with ast.parse() — pq=none + old profile (no PQ branches)',
  { skip: PYTHON3 ? false : PY_SKIP_REASON }, () => {
    const out = python(
      baseForm({ pq: 'none', config: 'old', opensslVersion: '1.1.1' }),
      Object.assign({}, BASE_OUTPUT, {
        protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
        tlsCurves: ['X25519', 'prime256v1', 'secp384r1'],
      }),
    );
    const r = astParse(out);
    assert.equal(r.status, 0,
      `ast.parse failed (exit ${r.status}):\nSTDERR:\n${r.stderr}\n--- rendered ---\n${out}`);
  });
