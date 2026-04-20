// test/screenshot.test.js — tests for scripts/screenshot.js.
//
// The script has two distinct surfaces:
//
//   1. Always-on safety guards — argument parsing, --help, the
//      SCG_GEN_SCREENSHOTS=1 opt-in refusal. These can be exercised
//      cheaply (no playwright, no dev server) and run on every
//      `npm test`.
//
//   2. End-to-end visual capture — boots `npm start`, drives
//      Playwright/Chromium, writes a PNG. This is heavy and noisy
//      (see scripts/screenshot.js header for rationale), so it is
//      gated behind SCG_RUN_SCREENSHOT_TEST=1 *and* requires
//      `playwright` to be installed (`npm install --save-dev
//      playwright && npx playwright install chromium`). The test
//      probe-skips if either precondition is missing, mirroring the
//      pattern from test/iis.test.js (pwsh) and test/python.test.js
//      (python3) — see AGENTS.md "Tests that depend on external
//      tools".
//
// To run the heavy end-to-end test:
//   SCG_RUN_SCREENSHOT_TEST=1 npm test

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO   = path.resolve(__dirname, '..');
const SCRIPT = path.join(REPO, 'scripts', 'screenshot.js');

function runScript(args, env = {}) {
  return spawnSync(
    process.execPath,
    [SCRIPT, ...args],
    {
      cwd: REPO,
      encoding: 'utf8',
      timeout: 300000,
      env: Object.assign({}, process.env, env),
    },
  );
}

// ────────── Always-on guard tests ──────────

test('screenshot: --help prints usage and exits 0', () => {
  const r = runScript(['--help']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /Usage: SCG_GEN_SCREENSHOTS=1 node scripts\/screenshot\.js/);
  assert.match(r.stdout, /--server/);
  assert.match(r.stdout, /--pq/);
  assert.match(r.stdout, /--full-page/);
});

test('screenshot: refuses to run without SCG_GEN_SCREENSHOTS=1 (exit 64)', () => {
  // Force the env var off explicitly so an enclosing CI shell can't
  // change the test's behaviour.
  const env = Object.assign({}, process.env);
  delete env.SCG_GEN_SCREENSHOTS;
  const r = spawnSync(
    process.execPath,
    [SCRIPT, '--server', 'nginx'],
    { cwd: REPO, encoding: 'utf8', timeout: 30000, env },
  );
  assert.equal(r.status, 64);
  assert.match(r.stderr, /refusing to run without SCG_GEN_SCREENSHOTS=1/);
});

test('screenshot: unknown option exits 2 before opt-in check', () => {
  const r = runScript(['--no-such-flag']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option: --no-such-flag/);
});

test('screenshot: unknown server (no latestVersion) exits 2', () => {
  const r = runScript(['--server', 'definitely-not-a-real-server']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no latestVersion for server 'definitely-not-a-real-server'/);
});

// ────────── Heavy end-to-end test (opt-in) ──────────

const E2E_ENABLED = process.env.SCG_RUN_SCREENSHOT_TEST === '1';

// Probe-once for playwright. We do NOT npm-install it here — that would
// silently bloat the test suite. If it's missing, skip with a clear hint.
const PLAYWRIGHT = (() => {
  if (!E2E_ENABLED) return null;
  try {
    require.resolve('playwright', { paths: [REPO] });
    return 'playwright';
  } catch (_) {
    return null;
  }
})();

const E2E_SKIP = !E2E_ENABLED
  ? 'set SCG_RUN_SCREENSHOT_TEST=1 to run the end-to-end screenshot test'
  : (!PLAYWRIGHT
    ? 'playwright is not installed (run `npm install --save-dev playwright && npx playwright install chromium`)'
    : false);

test('screenshot: end-to-end captures a non-empty PNG of the rendered page',
    { skip: E2E_SKIP }, async (t) => {
  // Budget generously: spawning `npm start` (webpack+browser-sync) plus
  // a chromium page load typically takes 30-60s on CI.
  t.diagnostic('this test boots the dev server and Chromium; expect ~1 min');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-shot-'));
  const out = path.join(tmp, 'nginx-intermediate.png');
  try {
    const r = runScript(
      ['--server', 'nginx', '--config', 'intermediate', '--pq', 'hybrid',
       '--out', out, '--wait-ms', '500'],
      { SCG_GEN_SCREENSHOTS: '1' },
    );
    assert.equal(r.status, 0,
      `screenshot exited ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.ok(fs.existsSync(out), `expected screenshot at ${out}`);
    const stat = fs.statSync(out);
    assert.ok(stat.size > 1024, `screenshot is suspiciously small (${stat.size} bytes)`);
    // PNG magic number: 89 50 4E 47 0D 0A 1A 0A
    const head = fs.readFileSync(out).slice(0, 8);
    assert.deepEqual(
      Array.from(head),
      [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
      'output is not a valid PNG (wrong magic bytes)');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
