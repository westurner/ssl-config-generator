#!/usr/bin/env node
// scripts/screenshot.js — opt-in Playwright helper that screenshots the
// rendered web page for one parameter set. Drives the live UI by URL
// fragment (every form field is in the validHashKeys allowlist in
// src/js/constants.js, so state.js reads the fragment on load and
// renders without any DOM clicking).
//
// This script is INTENTIONALLY OPT-IN. Reasons:
//   - Playwright + headless Chromium is a heavy dependency to drag into
//     `npm test` (the existing suite uses only node:test +
//     @babel/register).
//   - Image diffs are noisy: font hinting, anti-aliasing, scrollbar widths
//     and the rendered date in the output header all jitter.
//
// To run, install Playwright separately and set the env var:
//
//   npm install --save-dev playwright
//   npx playwright install chromium
//   SSL_GEN_SCREENSHOTS=1 node scripts/screenshot.js \
//       --server nginx --pq hybrid --config intermediate
//
// The renderer's date stamp is pinned to a fixed value when the page is
// loaded with `?det=1` in the query string (the live site's renderer
// honours the `now` parameter we expose via the same env hook in
// src/js/state.js — see DETERMINISTIC_DATE in scripts/render-grid.js for
// the matching off-line constant). For now this script just trims the
// first two header comment lines from any visual comparison.

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');

const configs = require('../src/js/configs.js');

function tryRequire(name) {
  try { return require(name); } catch (_) { return null; }
}

const ENABLED = process.env.SSL_GEN_SCREENSHOTS === '1';

// Probe-once / explain-clearly pattern. Mirrors test/iis.test.js (pwsh)
// and test/python.test.js (python3): if the dependency is missing or the
// opt-in env var is unset, exit cleanly with a hint instead of crashing.
function refuseIfDisabled() {
  if (!ENABLED) {
    process.stderr.write(
      'screenshot.js: refusing to run without SSL_GEN_SCREENSHOTS=1\n' +
      '  (Playwright is heavy and image diffs are noisy — set the env\n' +
      '  var to opt in for local visual-regression review.)\n');
    process.exit(64);
  }
}

function parseArgs(argv) {
  const o = {
    server: 'nginx',
    version: null,             // defaults to configs[server].latestVersion
    openssl: configs.openssl.latestVersion,
    config: 'intermediate',    // Mozilla profile
    hsts: true,
    ocsp: true,
    pq: 'hybrid',
    guideline: '5.7',
    out: null,                 // defaults to fixtures/screenshots/<auto>.png
    baseUrl: null,             // if set, skip serving and screenshot this URL
    fullPage: false,           // default crops to <main>
    waitMs: 1500,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--server':    o.server = argv[++i]; break;
      case '--version':   o.version = argv[++i]; break;
      case '--openssl':   o.openssl = argv[++i]; break;
      case '--config':    o.config = argv[++i]; break;
      case '--hsts':      o.hsts = argv[++i] !== 'false'; break;
      case '--ocsp':      o.ocsp = argv[++i] !== 'false'; break;
      case '--pq':        o.pq = argv[++i]; break;
      case '--guideline': o.guideline = argv[++i]; break;
      case '--out':       o.out = argv[++i]; break;
      case '--base-url':  o.baseUrl = argv[++i]; break;
      case '--full-page': o.fullPage = true; break;
      case '--wait-ms':   o.waitMs = parseInt(argv[++i], 10); break;
      case '-h':
      case '--help':
        process.stdout.write(
`Usage: SSL_GEN_SCREENSHOTS=1 node scripts/screenshot.js [options]

  --server <name>     server software (default: nginx)
  --version <ver>     server version (default: configs.<server>.latestVersion)
  --openssl <ver>     OpenSSL version (default: configs.openssl.latestVersion)
  --config <profile>  modern | intermediate | old (default: intermediate)
  --hsts true|false   default: true
  --ocsp true|false   default: true
  --pq <mode>         none | hybrid | only (default: hybrid)
  --guideline <ver>   default: 5.7
  --out <path>        output PNG (default: fixtures/screenshots/<auto>.png)
  --base-url <url>    skip starting a server, hit this base URL instead
  --full-page         capture the whole page (default: just <main>)
  --wait-ms <n>       extra wait after output settles (default: 1500)
`);
        process.exit(0);
        break;
      default:
        process.stderr.write(`unknown option: ${a}\n`);
        process.exit(2);
    }
  }
  if (!o.version) o.version = (configs[o.server] || {}).latestVersion;
  if (!o.version) {
    process.stderr.write(`no latestVersion for server '${o.server}'\n`);
    process.exit(2);
  }
  return o;
}

// Build the URL fragment exactly as src/js/state.js does
// (state.js: `server=…&version=…&config=…[&openssl=…][&hsts][&ocsp]&guideline=…[&pq=…]`).
function buildFragment(o) {
  let f = `server=${o.server}&version=${o.version}&config=${o.config}`;
  if (configs[o.server].usesOpenssl !== false) f += `&openssl=${o.openssl}`;
  if (configs[o.server].supportsHsts !== false && o.hsts) f += '&hsts';
  if (configs[o.server].supportsOcspStapling && o.ocsp) f += '&ocsp';
  f += `&guideline=${o.guideline}`;
  if (o.pq !== 'hybrid') f += `&pq=${o.pq}`;
  return f;
}

// Default output path mirrors the grid filename scheme so a screenshot
// and its config snapshot live next to each other under different
// extensions when both are checked in.
function defaultOutPath(o) {
  // eslint-disable-next-line global-require
  const axes = require('../src/js/grid-axes.js');
  const fname = axes.filenameFor({
    server: o.server,
    guideline: o.guideline,
    serverVersion: o.version,
    profile: o.config,
    pqMode: o.pq,
    hsts: o.hsts,
    ocsp: o.ocsp,
  }).replace(/\.[^.]+$/, '.png');
  return path.join('fixtures', 'screenshots', o.server, fname);
}

// Wait for an HTTP server to start responding. We poll once a second up
// to `timeoutMs` to keep the implementation dependency-free.
function waitForServer(url, timeoutMs = 30000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    function tick() {
      const req = http.get(url, (res) => {
        res.resume();
        if (res.statusCode && res.statusCode < 500) return resolve();
        retry();
      });
      req.on('error', retry);
      req.setTimeout(2000, () => { req.destroy(); retry(); });
    }
    function retry() {
      if (Date.now() - start > timeoutMs) {
        return reject(new Error(`timed out waiting for ${url}`));
      }
      setTimeout(tick, 1000);
    }
    tick();
  });
}

// Start `npm start` (webpack-dev/browser-sync) in the background, return
// a {url, kill} handle. browser-sync defaults to localhost:3001 (see
// AGENTS.md "Build & dev"). The caller MUST call kill() in a finally
// block to avoid leaking the dev-server child process.
function startDevServer() {
  const child = spawn('npm', ['start'], {
    cwd: path.resolve(__dirname, '..'),
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });
  // Surface webpack errors so users aren't left wondering why the
  // browser-sync URL never came up.
  child.stderr.on('data', d => process.stderr.write(`[npm start] ${d}`));
  return {
    url: 'http://localhost:3001/',
    kill: () => { try { child.kill('SIGTERM'); } catch (_) {} },
  };
}

async function main() {
  const opts = parseArgs(process.argv);
  refuseIfDisabled();

  const playwright = tryRequire('playwright');
  if (!playwright) {
    process.stderr.write(
      'screenshot.js: playwright is not installed.\n' +
      '  Install it with:  npm install --save-dev playwright\n' +
      '                    npx playwright install chromium\n');
    process.exit(64);
  }

  let server;
  let baseUrl = opts.baseUrl;
  if (!baseUrl) {
    server = startDevServer();
    baseUrl = server.url;
    await waitForServer(baseUrl);
  }

  const fragment = buildFragment(opts);
  const url = baseUrl.replace(/\/$/, '/') + '#' + fragment;
  const outPath = path.resolve(opts.out || defaultOutPath(opts));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  const browser = await playwright.chromium.launch();
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 1600 } });
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'load' });
    // Wait until the helper has rendered something into <pre id="output-config">.
    await page.waitForFunction(() => {
      const pre = document.getElementById('output-config');
      return pre && pre.textContent && pre.textContent.length > 0;
    }, { timeout: 30000 });
    if (opts.waitMs > 0) await page.waitForTimeout(opts.waitMs);
    if (opts.fullPage) {
      await page.screenshot({ path: outPath, fullPage: true });
    } else {
      const main = await page.$('main') || await page.$('body');
      await main.screenshot({ path: outPath });
    }
    process.stdout.write(`wrote ${path.relative(process.cwd(), outPath)}\n`);
  } finally {
    await browser.close();
    if (server) server.kill();
  }
}

main().catch(err => {
  process.stderr.write(`screenshot.js: ${err.stack || err.message}\n`);
  process.exit(1);
});
