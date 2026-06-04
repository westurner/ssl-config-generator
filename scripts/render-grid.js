#!/usr/bin/env node
// scripts/render-grid.js — materialise the helpers × params grid as a tree
// of snapshot files under fixtures/grid/.
//
// Invocation (must be run via the repo's babel/register hook so the ES-module
// helpers under src/js/helpers/ load — see the npm scripts):
//
//   node --require @babel/register scripts/render-grid.js [options]
//
// Options:
//   --out <dir>          output directory (default: fixtures/grid)
//   --server <name>      restrict to one helper (repeatable)
//   --guideline <ver>    restrict to one guideline (repeatable)
//   --config <profile>   restrict to one Mozilla profile: modern|intermediate|old
//   --hsts true|false    restrict to one HSTS setting
//   --ocsp true|false    restrict to one OCSP-stapling setting
//   --pq <mode>          restrict to one PQ mode: none|hybrid|only
//   --version <ver>      override server version for all rendered cells
//   --openssl <ver>      override OpenSSL version for all rendered cells
//   --only-changed       in-memory render only; write files whose content
//                        changed (or are new). Useful for partial regen.
//   --dry-run            print what WOULD be written; touch nothing.
//
// The renderer is the pure src/js/render.js (the same one src/js/state.js
// uses), so the snapshot output is byte-identical to what the live site
// generates for the same fragment. The runtime `generated YYYY-MM-DD …`
// header date is pinned to a fixed value (DETERMINISTIC_DATE below) so
// re-running the script on a different day does NOT churn every file.

const fs = require('fs');
const path = require('path');

const configs   = require('../src/js/configs.js');
const pureState = require('../src/js/render.js').default;
const axes      = require('../src/js/grid-axes.js');

// Pinned generation date for the rendered config header. Choosing a fixed
// epoch-style date (rather than `Date.now()`) means re-running the script
// on different days does not cause the entire grid to "change" in git.
const DETERMINISTIC_DATE = new Date('1970-01-01T00:00:00Z');

// Bundled guideline JSONs the renderer can consume synchronously. Keep in
// sync with src/js/grid-axes.js GUIDELINES.
function loadGuideline(g) {
  return require(`../src/static/guidelines/${g}.json`);
}

// Per-helper render template. Mirrors the loop in src/js/index.js:18-22.
function loadTemplate(server) {
  return require(`../src/js/helpers/${server}.js`).default;
}

function parseArgs(argv) {
  const out = {
    outDir: 'fixtures/grid',
    servers: null,         // null = all
    guidelines: null,      // null = all
    config: null,          // null = all profiles
    hsts: null,            // null = all (true/false)
    ocsp: null,            // null = all (true/false)
    pq: null,              // null = all modes
    version: null,         // null = use per-helper latestVersion
    openssl: null,         // null = use per-helper default
    onlyChanged: false,
    dryRun: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--out':         out.outDir = argv[++i]; break;
      case '--server':      (out.servers = out.servers || []).push(argv[++i]); break;
      case '--guideline':   (out.guidelines = out.guidelines || []).push(argv[++i]); break;
      case '--config':      out.config = argv[++i]; break;
      case '--hsts':        out.hsts = argv[++i] !== 'false'; break;
      case '--ocsp':        out.ocsp = argv[++i] !== 'false'; break;
      case '--pq':          out.pq = argv[++i]; break;
      case '--version':     out.version = argv[++i]; break;
      case '--openssl':     out.openssl = argv[++i]; break;
      case '--only-changed':out.onlyChanged = true; break;
      case '--dry-run':     out.dryRun = true; break;
      case '-h':
      case '--help':
        process.stdout.write(
`Usage: node --require @babel/register scripts/render-grid.js [options]

  --out <dir>           output directory (default: fixtures/grid)
  --server <name>       restrict to one helper (repeatable)
  --guideline <ver>     restrict to one guideline (repeatable)
  --config <profile>    restrict to one Mozilla profile: modern|intermediate|old
  --hsts true|false     restrict to one HSTS setting
  --ocsp true|false     restrict to one OCSP-stapling setting
  --pq <mode>           restrict to one PQ mode: none|hybrid|only
  --version <ver>       override server version for all rendered cells
  --openssl <ver>       override OpenSSL version for all rendered cells
  --only-changed        write files whose content changed
  --dry-run             print what would be written
`);
        process.exit(0);
        break;
      default:
        process.stderr.write(`unknown option: ${a}\n`);
        process.exit(2);
    }
  }
  return out;
}

function renderOne(cell, guidelineDataCache) {
  if (!guidelineDataCache[cell.guideline]) {
    guidelineDataCache[cell.guideline] = loadGuideline(cell.guideline);
  }
  const state = pureState({
    server:         cell.server,
    serverVersion:  cell.serverVersion,
    opensslVersion: cell.opensslVersion,
    config:         cell.profile,
    hsts:           cell.hsts,
    ocsp:           cell.ocsp,
    pqMode:         cell.pqMode,
    guideline:      cell.guideline,
    guidelineData:  guidelineDataCache[cell.guideline],
    origin:         'https://ssl-config.mozilla.org',
    pathname:       '/',
    now:            DETERMINISTIC_DATE,
  });
  const template = loadTemplate(cell.server);
  return template(state.form, state.output);
}

function main() {
  const opts = parseArgs(process.argv);
  const repoRoot = path.resolve(__dirname, '..');
  const outRoot  = path.resolve(repoRoot, opts.outDir);

  const servers = opts.servers || axes.SERVERS;
  const guidelines = opts.guidelines || axes.GUIDELINES;

  let written = 0, skipped = 0, total = 0;
  const guidelineDataCache = {};

  for (const server of servers) {
    if (!configs[server]) {
      process.stderr.write(`unknown server: ${server}\n`);
      process.exit(2);
    }
    for (const cell of axes.gridFor(server, { guidelines })) {
      // Apply optional single-cell filters
      if (opts.config !== null && cell.profile !== opts.config) continue;
      if (opts.hsts !== null && cell.hsts !== opts.hsts) continue;
      if (opts.ocsp !== null && cell.ocsp !== opts.ocsp) continue;
      if (opts.pq !== null && cell.pqMode !== opts.pq) continue;
      // Override version / openssl when the caller specifies them
      if (opts.version !== null) cell.serverVersion = opts.version;
      if (opts.openssl !== null) cell.opensslVersion = opts.openssl;
      total++;
      const fname = axes.filenameFor({
        server: cell.server,
        guideline: cell.guideline,
        serverVersion: cell.serverVersion,
        profile: cell.profile,
        pqMode: cell.pqMode,
        hsts: cell.hsts,
        ocsp: cell.ocsp,
      });
      const dir = path.join(outRoot, server);
      const fpath = path.join(dir, fname);
      let content;
      try {
        content = renderOne(cell, guidelineDataCache);
      } catch (e) {
        process.stderr.write(`ERROR rendering ${fname}: ${e.message}\n`);
        throw e;
      }
      // Ensure trailing newline so `git diff` shows the last line cleanly
      // without a "No newline at end of file" marker.
      if (!content.endsWith('\n')) content += '\n';

      if (opts.onlyChanged && fs.existsSync(fpath)) {
        const existing = fs.readFileSync(fpath, 'utf8');
        if (existing === content) { skipped++; continue; }
      }
      if (opts.dryRun) {
        process.stdout.write(`would write ${path.relative(repoRoot, fpath)} (${content.length} bytes)\n`);
      } else {
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(fpath, content);
      }
      written++;
    }
  }

  // Index file lists every cell so external tools (and the snapshot test)
  // can iterate without re-deriving the cross product.
  if (!opts.dryRun) {
    const indexPath = path.join(outRoot, '_index.json');
    const all = [];
    for (const server of servers) {
      for (const cell of axes.gridFor(server, { guidelines })) {
        all.push(Object.assign({}, cell, {
          file: path.posix.join(server, axes.filenameFor({
            server: cell.server,
            guideline: cell.guideline,
            serverVersion: cell.serverVersion,
            profile: cell.profile,
            pqMode: cell.pqMode,
            hsts: cell.hsts,
            ocsp: cell.ocsp,
          })),
        }));
      }
    }
    fs.mkdirSync(outRoot, { recursive: true });
    fs.writeFileSync(indexPath, JSON.stringify({
      generated: 'render-grid.js',
      deterministicDate: DETERMINISTIC_DATE.toISOString().slice(0, 10),
      cells: all,
    }, null, 2) + '\n');
  }

  process.stdout.write(`render-grid: ${written} written, ${skipped} unchanged, ${total} total\n`);
}

main();
