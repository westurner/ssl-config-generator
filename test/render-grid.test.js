// test/render-grid.test.js — opt-in CLI tests for scripts/render-grid.js.
//
// These shell out to a child `node --require @babel/register
// scripts/render-grid.js …` to exercise the actual command-line surface
// (argument parsing, dry-run, --only-changed, file writes). They are
// gated behind `SCG_RUN_RENDER_GRID_TEST=1` because:
//
//   - they spawn a fresh Node process per test (each ~1s of @babel/register
//     warm-up), which would noticeably slow the default `npm test` run;
//   - the snapshot byte-equality assertion is already covered by
//     test/grid.test.js — these tests are about the *script*, not the
//     renderer.
//
// To run:    SCG_RUN_RENDER_GRID_TEST=1 npm test
//
// Mirrors the probe-once / skip-with-reason pattern documented in
// AGENTS.md (Tests that depend on external tools).

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ENABLED = process.env.SCG_RUN_RENDER_GRID_TEST === '1';
const SKIP = ENABLED ? false
  : 'set SCG_RUN_RENDER_GRID_TEST=1 to run render-grid CLI tests';

const REPO   = path.resolve(__dirname, '..');
const SCRIPT = path.join(REPO, 'scripts', 'render-grid.js');

// Run the script in a child Node process. Returns { status, stdout, stderr }.
// Always passes --require @babel/register so the ES-module helpers load,
// matching the npm-script invocation.
function runScript(args, opts = {}) {
  const r = spawnSync(
    process.execPath,
    ['--require', '@babel/register', SCRIPT, ...args],
    Object.assign({
      cwd: REPO,
      encoding: 'utf8',
      timeout: 120000,
      env: Object.assign({}, process.env),
    }, opts),
  );
  return r;
}

test('render-grid: --help prints usage and exits 0', { skip: SKIP }, () => {
  const r = runScript(['--help']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /Usage: node --require @babel\/register scripts\/render-grid\.js/);
  assert.match(r.stdout, /--only-changed/);
  assert.match(r.stdout, /--dry-run/);
});

test('render-grid: unknown option exits 2', { skip: SKIP }, () => {
  const r = runScript(['--no-such-flag']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option: --no-such-flag/);
});

test('render-grid: unknown server exits 2', { skip: SKIP }, () => {
  const r = runScript(['--server', 'definitely-not-a-real-server', '--dry-run']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown server: definitely-not-a-real-server/);
});

test('render-grid: --dry-run writes nothing and prints "would write" lines', { skip: SKIP }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-rg-dry-'));
  try {
    const r = runScript([
      '--out', tmp,
      '--server', 'nginx',
      '--guideline', '5.7',
      '--config', 'intermediate',
      '--hsts', 'true',
      '--ocsp', 'true',
      '--pq', 'none',
      '--dry-run',
    ]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /would write .*nginx.*\.conf/);
    assert.match(r.stdout, /render-grid: \d+ written, \d+ unchanged, \d+ total/);
    // Dry run must not create any files in the out dir.
    const entries = fs.readdirSync(tmp);
    assert.equal(entries.length, 0,
      `dry-run created files in ${tmp}: ${entries.join(', ')}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('render-grid: writes a fixture that matches the committed snapshot', { skip: SKIP }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-rg-write-'));
  try {
    const r = runScript([
      '--out', tmp,
      '--server', 'nginx',
      '--guideline', '5.7',
      '--config', 'intermediate',
      '--hsts', 'true',
      '--ocsp', 'true',
      '--pq', 'none',
    ]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    // Locate the single nginx file we just rendered and compare it to
    // the corresponding committed fixture (byte-equal except for any
    // version drift driven by configs.js, which both runs share).
    const nginxDir = path.join(tmp, 'nginx');
    const written = fs.readdirSync(nginxDir);
    assert.equal(written.length, 1, `expected exactly 1 file, got ${written.join(', ')}`);
    const got = fs.readFileSync(path.join(nginxDir, written[0]), 'utf8');
    const baseline = path.join(REPO, 'fixtures', 'grid', 'nginx', written[0]);
    assert.ok(fs.existsSync(baseline),
      `no committed baseline at ${baseline} — re-run \`npm run render-grid\``);
    const want = fs.readFileSync(baseline, 'utf8');
    assert.equal(got, want,
      'rendered file diverged from committed fixture');
    // _index.json is always rewritten alongside the cells.
    assert.ok(fs.existsSync(path.join(tmp, '_index.json')));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('render-grid: --only-changed against committed fixtures writes 0 cells',
    { skip: SKIP }, () => {
  // Re-render straight back into fixtures/grid with --only-changed for a
  // narrow slice. If the renderer is deterministic and the snapshots are
  // current, nothing should change.
  const r = runScript([
    '--server', 'nginx',
    '--guideline', '5.7',
    '--config', 'modern',
    '--hsts', 'true',
    '--ocsp', 'true',
    '--pq', 'none',
    '--only-changed',
    '--dry-run',     // still dry-run so we don't risk touching git state
  ]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  // total should be 1 for this single-cell slice.
  assert.match(r.stdout, /render-grid: \d+ written, \d+ unchanged, 1 total/);
});
