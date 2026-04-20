// test/url-fragment.test.js — verify URL-fragment parsing accepts
// both the short ("flag-only") and full ("key=true") spellings of
// boolean toggles like `hsts` and `ocsp`.
//
// The browser entry point (src/js/index.js) walks every entry of
// `new URLSearchParams(window.location.hash.substr(1))`. For
// checkboxes it converts each value to a boolean via
// `hashValueToBool` from utils.js. This file exercises that helper
// directly (pure, no DOM) so the supported URL shapes are pinned by
// regression tests.
//
// Supported short form:   #server=nginx&hsts&ocsp
// Supported full  form:   #server=nginx&hsts=true&ocsp=true
// Explicit disable:       #server=nginx&hsts=false&ocsp=false

import test from 'node:test';
import assert from 'node:assert/strict';

import { hashValueToBool } from '../src/js/utils.js';
import { validHashKeys } from '../src/js/constants.js';

// Mirror of src/js/index.js's per-entry checkbox logic, minus the DOM
// lookup. Returns a {hsts, ocsp, ...} map of boolean states for any
// keys present in the hash that are also valid hash keys.
function parseFragmentBooleans (hash, keys = ['hsts', 'ocsp']) {
  const out = {};
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  for (const [k, v] of params.entries()) {
    if (!validHashKeys.includes(k)) continue;
    if (keys.includes(k)) out[k] = hashValueToBool(v);
  }
  return out;
}

test('hashValueToBool: short flag-only form (value === "") is truthy', () => {
  assert.equal(hashValueToBool(''), true);
});

test('hashValueToBool: undefined / null yield null (key absent — no decision)', () => {
  // Distinct from `''` (flag-only present → true). `null` lets callers
  // tell "key not in the fragment" apart from "key present without a value".
  assert.equal(hashValueToBool(undefined), null);
  assert.equal(hashValueToBool(null), null);
});

test('hashValueToBool: explicit "true" / "false" parse as expected', () => {
  assert.equal(hashValueToBool('true'), true);
  assert.equal(hashValueToBool('false'), false);
});

test('hashValueToBool: case-insensitive and accepts 1/0/on/off/yes/no', () => {
  for (const t of ['TRUE', 'True', '1', 'on', 'ON', 'yes']) {
    assert.equal(hashValueToBool(t), true, `expected truthy for ${t}`);
  }
  for (const f of ['FALSE', 'False', '0', 'off', 'OFF', 'no']) {
    assert.equal(hashValueToBool(f), false, `expected falsy for ${f}`);
  }
});

test('short URL form: ?server=nginx&hsts&ocsp enables both', () => {
  const got = parseFragmentBooleans('#server=nginx&hsts&ocsp');
  assert.deepEqual(got, { hsts: true, ocsp: true });
});

test('full URL form: ?server=nginx&hsts=true&ocsp=true enables both', () => {
  const got = parseFragmentBooleans('#server=nginx&hsts=true&ocsp=true');
  assert.deepEqual(got, { hsts: true, ocsp: true });
});

test('explicit disable: ?server=nginx&hsts=false&ocsp=false disables both', () => {
  const got = parseFragmentBooleans('#server=nginx&hsts=false&ocsp=false');
  assert.deepEqual(got, { hsts: false, ocsp: false });
});

test('mixed: ?server=nginx&hsts&ocsp=false enables hsts, disables ocsp', () => {
  const got = parseFragmentBooleans('#server=nginx&hsts&ocsp=false');
  assert.deepEqual(got, { hsts: true, ocsp: false });
});

test('full guideline+pq URL still works (regression for emitted fragment shape)', () => {
  // src/js/render.js always emits `&hsts=<bool>&ocsp=<bool>` in the
  // `output.fragment` string; ensure round-tripping that exact shape
  // stays supported.
  const got = parseFragmentBooleans(
    '#server=nginx&version=1.27.0&config=intermediate&openssl=3.5.0' +
    '&guideline=5.7&hsts=true&ocsp=false&pq=hybrid'
  );
  assert.deepEqual(got, { hsts: true, ocsp: false });
});

test('absent keys do not appear in result (no false-default injection)', () => {
  const got = parseFragmentBooleans('#server=nginx&config=modern');
  assert.deepEqual(got, {});
});
