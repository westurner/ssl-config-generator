// Single source of truth for the "axes" the off-line grid generator and the
// snapshot test iterate over. Both scripts/render-grid.js and
// test/_helpers/fixtures.js (re-export) import from here so the cross-product
// of "what config combinations exist" stays defined in exactly one place.
//
// The grid is defined by a Cartesian product over these axes:
//
//   server     × Mozilla profile × pqMode × hsts × ocsp × guideline
//
// The first axis (server) lives in src/js/configs.js (Object.keys(configs)
// minus 'openssl', which is the linked-OpenSSL pseudo-entry, not a server).
// The remaining axes are listed below, in the SAME order they appear in
// generated filenames so files sort by the axis you most often diff.

const configs = require('./configs.js');

// Mozilla Server-Side TLS profiles. Order matches the radio buttons in
// templates/index.ejs and the harness.PROFILES export.
const PROFILES = ['modern', 'intermediate', 'old'];

// Post-Quantum modes. Order is "least PQ" → "most PQ" so a `ls` listing
// reads naturally. Matches state.js validation (state.js: 'none'|'hybrid'|
// 'only') and PQ_MODES in test/_helpers/fixtures.js.
const PQ_MODES = ['none', 'hybrid', 'only'];

// Bundled Mozilla guideline JSONs the renderer can consume synchronously.
// We deliberately limit grid generation to BUNDLED guidelines (those that
// live under src/static/guidelines/*.json and are require()'d at build
// time) rather than the runtime-fetchable older guidelines, so grid
// generation has no network dependency and is fully reproducible.
const GUIDELINES = ['5.7', '6.0'];

// Booleans rendered as integers in filenames so the sort order is stable
// (`hsts0` < `hsts1`) and so a single character distinguishes them in a
// long filename listing.
const BOOLS = [false, true];

// Server-software keys, sorted alphabetically. 'openssl' is excluded
// because it's the pseudo-entry tracking the linked OpenSSL version (used
// for the eolBefore/tls13 floors), not a server in its own right.
const SERVERS = Object.keys(configs).filter(s => s !== 'openssl').sort();

// File extension per helper. Picked so a syntax-highlighting editor or
// GitHub's blob viewer renders the snapshot with sensible color, which
// makes diffs much easier to read. Defaults to '.conf' for everything not
// listed (most server configs are key=value text and read fine as `.conf`).
const FILE_EXTENSIONS = {
  apache:        'conf',
  awsalb:        'json',
  awselb:        'json',
  caddy:         'Caddyfile',
  coturn:        'conf',
  dovecot:       'conf',
  exim:          'conf',
  gnutls:        'conf',
  go:            'go',
  haproxy:       'cfg',
  iis:           'ps1',
  jetty:         'xml',
  kubernetes:    'yaml',
  lighttpd:      'conf',
  litespeed:     'conf',
  mysql:         'cnf',
  nginx:         'conf',
  openldap:      'conf',
  openlitespeed: 'conf',
  opensslcnf:    'cnf',
  oraclehttp:    'conf',
  postfix:       'cf',
  postgresql:    'conf',
  proftpd:       'conf',
  python:        'py',
  redis:         'conf',
  rust:          'rs',
  s2n:           'c',
  squid:         'conf',
  stunnel:       'conf',
  tomcat:        'xml',
  traefik:       'toml',
};
function extensionFor(server) {
  return FILE_EXTENSIONS[server] || 'conf';
}

// Map "is HSTS supported by this server?" / "is OCSP supported by this
// server (at its latest pinned version)?" so the grid generator can SKIP
// combinations that the renderer would degenerate into a no-op anyway.
//
// The renderer doesn't crash on `hsts=true` for a non-HTTP server — it
// just clears form.hsts (state.js / render.js: `hsts && supportsHsts !==
// false`). Skipping these axes at the GRID level keeps the file count
// down without losing any information that would actually appear in a
// rendered config.
function hstsAxisFor(server) {
  return configs[server].supportsHsts === false ? [false] : BOOLS;
}
function ocspAxisFor(server) {
  // supportsOcspStapling is either falsy, true, or a min-version string.
  // We pin serverVersion to latestVersion in the grid (see fragmentFor()
  // below), so any non-falsy value gates as "supported".
  return configs[server].supportsOcspStapling ? BOOLS : [false];
}
function pqAxisFor(server) {
  // Helpers without a PQ codepath (configs.js supportsPq unset) emit
  // identical text for all three pq= modes, modulo the version-tags
  // header. Keep all three so the grid documents that fact, but the
  // resulting files differ only in the comment header.
  return PQ_MODES;
}

// Filename rules. Fixed axis order so files sort alphabetically by what
// you most often want to vary (profile first → pq → hsts → ocsp).
//   <server>__g<guideline>__v<serverVersion>__<profile>__pq-<mode>__hsts<0|1>__ocsp<0|1>.<ext>
//
// Notes:
//   - '__' (double underscore) separates axes; '-' separates value words
//     inside a single axis.
//   - Server version is included so a file is self-describing — re-running
//     the grid after a configs.js latestVersion bump produces a new file
//     name (and `git mv` of the old one), making the version change
//     reviewable rather than silently drifting cipher / protocol output.
function filenameFor({ server, guideline, serverVersion, profile, pqMode, hsts, ocsp }) {
  const ext = extensionFor(server);
  const v = String(serverVersion).replace(/[^A-Za-z0-9._-]/g, '_');
  const g = String(guideline).replace(/[^A-Za-z0-9._-]/g, '_');
  const h = hsts ? 1 : 0;
  const o = ocsp ? 1 : 0;
  return `${server}__g${g}__v${v}__${profile}__pq-${pqMode}__hsts${h}__ocsp${o}.${ext}`;
}

// Inverse of filenameFor — used by the snapshot test to recover the axis
// values from a fixture path so it can re-render and compare.
function parseFilename(name) {
  // Strip extension first.
  const dot = name.lastIndexOf('.');
  const stem = dot === -1 ? name : name.slice(0, dot);
  const parts = stem.split('__');
  if (parts.length !== 7) {
    throw new Error(`grid: cannot parse filename: ${name}`);
  }
  const [server, gpart, vpart, profile, pqpart, hstspart, ocsppart] = parts;
  if (!gpart.startsWith('g')) throw new Error(`grid: bad guideline in ${name}`);
  if (!vpart.startsWith('v')) throw new Error(`grid: bad version in ${name}`);
  if (!pqpart.startsWith('pq-')) throw new Error(`grid: bad pq in ${name}`);
  if (!hstspart.startsWith('hsts')) throw new Error(`grid: bad hsts in ${name}`);
  if (!ocsppart.startsWith('ocsp')) throw new Error(`grid: bad ocsp in ${name}`);
  return {
    server,
    guideline: gpart.slice(1),
    serverVersion: vpart.slice(1),
    profile,
    pqMode: pqpart.slice(3),
    hsts: hstspart.slice(4) === '1',
    ocsp: ocsppart.slice(4) === '1',
  };
}

// Per-server "what version of OpenSSL do we pin in the grid?" — fixed so
// the cipher / protocol output is reproducible across days. Defaults to
// configs.openssl.latestVersion. Servers with usesOpenssl:false ignore it.
function opensslVersionFor(server) {
  return configs.openssl.latestVersion;
}

// Per-server "what version of the server do we pin in the grid?" — fixed
// to configs[server].latestVersion. Bumping that field in configs.js
// triggers a deliberate grid rename + re-render on the next run.
function serverVersionFor(server) {
  return configs[server].latestVersion;
}

// Build the full axis catalogue for one server. Filters out boolean axes
// the helper can't express so the resulting cross product has no
// degenerate duplicates. (See hstsAxisFor / ocspAxisFor above.)
//
// Profile axis is also filtered against the loaded guideline JSON: 6.0
// dropped the 'old' profile, so a (guideline=6.0, profile='old') cell
// would crash the renderer with a missing `configurations.old`. Callers
// pass `profilesFor(guideline)` (or omit profiles entirely to get the
// safe intersection).
function profilesFor(guideline) {
  if (guideline === '6.0') return ['modern', 'intermediate'];
  return PROFILES.slice();
}

function* gridFor(server, { guidelines = GUIDELINES, profiles = null } = {}) {
  const serverVersion = serverVersionFor(server);
  const opensslVersion = opensslVersionFor(server);
  for (const guideline of guidelines) {
    const profileList = profiles || profilesFor(guideline);
    for (const profile of profileList) {
      for (const pqMode of pqAxisFor(server)) {
        for (const hsts of hstsAxisFor(server)) {
          for (const ocsp of ocspAxisFor(server)) {
            yield {
              server,
              serverVersion,
              opensslVersion,
              guideline,
              profile,
              pqMode,
              hsts,
              ocsp,
            };
          }
        }
      }
    }
  }
}

module.exports = {
  PROFILES,
  PQ_MODES,
  GUIDELINES,
  BOOLS,
  SERVERS,
  FILE_EXTENSIONS,
  extensionFor,
  hstsAxisFor,
  ocspAxisFor,
  pqAxisFor,
  filenameFor,
  parseFilename,
  serverVersionFor,
  opensslVersionFor,
  profilesFor,
  gridFor,
};
