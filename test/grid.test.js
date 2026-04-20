// test/grid.test.js — snapshot suite that diffs every fixture under
// fixtures/grid/ against a fresh re-render. Updates are made via
// `npm run render-grid`, NOT by editing the .conf files by hand.
//
// Layered with the other two test categories:
//
//   1. Property invariants  — test/<helper>.test.js + test/_helpers/harness.js
//                             ("the helper must NEVER emit RC4 in modern…")
//   2. Exact-output snapshots (THIS FILE) — fixtures/grid/<server>/*
//                             ("the helper's output for cell (X,Y,Z) is
//                             exactly this byte sequence")
//   3. Visual snapshots     — opt-in only via SCG_GEN_SCREENSHOTS=1 +
//                             scripts/screenshot.js (PNGs of the rendered
//                             web page; see AGENTS.md)
//
// They are complementary: invariants catch "this future change must not
// reintroduce a forbidden token anywhere"; snapshots catch "this change
// modified the rendered output for these specific cells, and a reviewer
// should look at the diff".

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import pureState from '../src/js/render.js';
import { parseFilename } from '../src/js/grid-axes.js';

const REPO = path.resolve(__dirname, '..');
const GRID = path.join(REPO, 'fixtures', 'grid');

// Same constant as scripts/render-grid.js. Kept independent so a stray
// edit to one immediately fails the snapshot test in the other.
const DETERMINISTIC_DATE = new Date('1970-01-01T00:00:00Z');

function loadGuideline(g) {
  return JSON.parse(fs.readFileSync(
    path.join(REPO, 'src', 'static', 'guidelines', `${g}.json`),
    'utf8'));
}

function loadTemplate(server) {
  // Synchronous require through @babel/register (the test runner is
  // already invoked with `--require @babel/register`, see package.json).
  // eslint-disable-next-line global-require
  return require(`../src/js/helpers/${server}.js`).default;
}

function listGridFiles() {
  if (!fs.existsSync(GRID)) return [];
  const out = [];
  for (const server of fs.readdirSync(GRID)) {
    const dir = path.join(GRID, server);
    if (!fs.statSync(dir).isDirectory()) continue;
    for (const fname of fs.readdirSync(dir)) {
      if (fname.startsWith('_') || fname.startsWith('.')) continue;
      out.push({ server, fname, fpath: path.join(dir, fname) });
    }
  }
  return out;
}

const FILES = listGridFiles();

const SKIP_REASON = FILES.length === 0
  ? 'fixtures/grid is empty — run `npm run render-grid` to materialise it'
  : false;

test('grid: at least one fixture exists', { skip: SKIP_REASON }, () => {
  assert.ok(FILES.length > 0);
});

const guidelineCache = {};
function getGuideline(g) {
  if (!guidelineCache[g]) guidelineCache[g] = loadGuideline(g);
  return guidelineCache[g];
}

for (const { server, fname, fpath } of FILES) {
  test(`grid snapshot: ${server}/${fname}`, { skip: SKIP_REASON }, () => {
    const cell = parseFilename(fname);
    assert.equal(cell.server, server,
      `filename server (${cell.server}) must match its directory (${server})`);

    const state = pureState({
      server:         cell.server,
      serverVersion:  cell.serverVersion,
      // Match scripts/render-grid.js: pin to configs.openssl.latestVersion
      // implicitly via the same opensslVersionFor helper. We re-derive
      // here from configs.js to avoid coupling the test to the script.
      // eslint-disable-next-line global-require
      opensslVersion: require('../src/js/configs.js').openssl.latestVersion,
      config:         cell.profile,
      hsts:           cell.hsts,
      ocsp:           cell.ocsp,
      pqMode:         cell.pqMode,
      guideline:      cell.guideline,
      guidelineData:  getGuideline(cell.guideline),
      origin:         'https://ssl-config.mozilla.org',
      pathname:       '/',
      now:            DETERMINISTIC_DATE,
    });
    const template = loadTemplate(cell.server);
    let rendered = template(state.form, state.output);
    if (!rendered.endsWith('\n')) rendered += '\n';

    const expected = fs.readFileSync(fpath, 'utf8');
    if (rendered !== expected) {
      // Provide a hint that this is a snapshot drift, not a logic bug.
      assert.equal(rendered, expected,
        `snapshot drift in ${path.relative(REPO, fpath)} — ` +
        `re-run \`npm run render-grid\` if the change is intentional`);
    }
  });
}
