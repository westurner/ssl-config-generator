// Shared test fixtures for helper unit tests.
//
// These objects mirror the shape produced by src/js/state.js for each Mozilla
// guideline profile (modern / intermediate / old), so a helper called with
// makeForm() / makeOutput() sees inputs that are byte-compatible with what it
// gets in production. The cipher / suite / curve data is taken from
// src/static/guidelines/5.7.json (the most recent guideline that still defines
// all three profiles, including 'old' with its 3DES tail used for the
// forbidden-primitive scan).

import test from 'node:test'; // re-exported convenience: not used here, but
                              // keeps the dependency surface in one place.

// PROFILES and PQ_MODES are re-exported from src/js/grid-axes.js so the
// off-line grid generator (scripts/render-grid.js) and the test fixtures
// share a single source of truth for "which axis values exist". Adding a
// fourth Mozilla profile or a fourth PQ mode means editing grid-axes.js
// once and every consumer picks it up.
import { PROFILES as _PROFILES, PQ_MODES as _PQ_MODES } from '../../src/js/grid-axes.js';
export const PROFILES = _PROFILES;
export const PQ_MODES = _PQ_MODES;

// PQ surface (mirrors src/js/state.js's pqMode + form.pq). Tests that need
// to exercise PQ codepaths construct fixtures via:
//   makeForm({ pq: 'only' })
//   makeOutput(profile, { pqMode: 'only', supportsPq: true })
// The 'none' / 'hybrid' / 'only' values match what state.js writes onto
// output.pqMode (state.js:206) and form.pq (state.js:183) — and what the
// HTML form posts (templates/index.ejs:139, value="hybrid"). 'hybrid' is
// the standard PQ-TLS term (NIST FIPS 203, draft-ietf-tls-hybrid-design,
// draft-kwiatkowski-tls-ecdhe-mlkem); helpers MUST use the same spelling.
// PQ_GROUPS lists the IANA-assigned hybrid ML-KEM codepoints that helpers
// with a PQ codepath are expected to surface (as group tokens, comments,
// or both) when output.supportsPq is true.
export const PQ_GROUPS = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024'];

// Per-profile snapshot of guideline 5.7. Embedded inline (rather than read at
// runtime from the JSON file) so the test fixtures are stable across
// guideline updates and so a future guideline-data refactor doesn't silently
// alter what a "modern" / "intermediate" / "old" profile means in tests.
const PROFILE_DATA = {
  modern: {
    protocols: ['TLSv1.3'],
    ciphers: {
      openssl: [],
      iana: [],
    },
    ciphersuites: [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
    ],
    tlsCurves: ['X25519', 'prime256v1', 'secp384r1'],
    serverPreferredOrder: false,
    dhParamSize: null,
  },
  intermediate: {
    protocols: ['TLSv1.2', 'TLSv1.3'],
    ciphers: {
      openssl: [
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-CHACHA20-POLY1305',
      ],
      iana: [
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
      ],
    },
    ciphersuites: [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
    ],
    tlsCurves: ['X25519', 'prime256v1', 'secp384r1'],
    serverPreferredOrder: false,
    dhParamSize: 2048,
  },
  old: {
    // NOTE: state.js emits 'TLSv1' (not 'TLSv1.0') for the legacy floor; some
    // helpers special-case that token (e.g. haproxy maps it to "TLSv1.0" for
    // ssl-min-ver). Tests must use the same spelling state.js does.
    protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
    ciphers: {
      openssl: [
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-CHACHA20-POLY1305',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-RSA-AES128-SHA256',
        'AES128-GCM-SHA256',
        'AES256-GCM-SHA384',
        'AES128-SHA256',
        'AES256-SHA256',
        'AES128-SHA',
        'AES256-SHA',
        'DES-CBC3-SHA',
      ],
      iana: [
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      ],
    },
    ciphersuites: [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
    ],
    tlsCurves: ['X25519', 'prime256v1', 'secp384r1'],
    serverPreferredOrder: true,
    dhParamSize: 1024,
  },
};

// Translate the configs.js cipherFormat ('openssl' | 'iana' | 'go') into the
// list of ciphers that state.js would put in output.ciphers. Note that
// state.js (state.js:140) treats cipherFormat === 'go' as IANA names: the Go
// stdlib's tls package and Caddy both consume IANA cipher names.
function _ciphersForFormat(profile, format) {
  if (format === 'openssl' || format === 'iana') {
    return PROFILE_DATA[profile].ciphers[format].slice();
  }
  if (format === 'go') {
    // state.js: `cipherFormat === 'go' ? ssc.ciphers['iana'] : ssc.ciphers[cipherFormat]`
    return PROFILE_DATA[profile].ciphers.iana.slice();
  }
  throw new Error(`unknown cipherFormat: ${format}`);
}

export function ciphersFor(profile, format) {
  return _ciphersForFormat(profile, format);
}

// Build an output object for a given profile, optionally overriding any
// fields. The cipherFormat option controls which cipher list ends up in
// output.ciphers (defaults to 'openssl', matching most helpers).
export function makeOutput(profile, { cipherFormat = 'openssl', ...overrides } = {}) {
  if (!PROFILE_DATA[profile]) throw new Error(`unknown profile: ${profile}`);
  const data = PROFILE_DATA[profile];
  const ciphers = _ciphersForFormat(profile, cipherFormat);
  return Object.assign({
    header: 'generated 1970-01-01, Mozilla Guideline v5.7',
    link: 'https://example.invalid/#config=' + profile,
    date: '1970-01-01',
    fragment: '5.7',
    origin: 'https://example.invalid',
    latestVersion: undefined,
    oldestClients: [],
    hasVersions: true,
    showSupports: true,
    supportsHsts: true,
    supportsOcspStapling: true,
    usesOpenssl: true,

    protocols: data.protocols.slice(),
    ciphers,
    cipherSuites: data.ciphersuites.slice(),
    tlsCurves: data.tlsCurves.slice(),
    serverPreferredOrder: data.serverPreferredOrder,

    hstsMaxAge: 63072000,
    hstsRedirectCode: 308,

    dhCommand: 'curl https://example.invalid/ffdhe' +
      (data.dhParamSize || 2048) + '.txt',
    dhParamSize: data.dhParamSize,
    // Mirror state.js:214 — only true DHE-/_DHE_ tokens count, not ECDHE.
    // The `:`/`_` boundary check excludes substring matches inside ECDHE-
    // and TLS_ECDHE_… cipher names.
    usesDhe: data.ciphers.openssl.join(':').includes(':DHE-')
          || data.ciphers.openssl.join(':').startsWith('DHE-')
          || data.ciphers.iana.join(':').includes('_DHE_'),

    // Per-helper capability flags (configs.js / state.js). Tests overriding
    // these can opt out of curve / cipher / PQ presence assertions in the
    // harness for helpers that legitimately cannot express the knob (e.g.
    // AWS ALB, s2n-tls). Defaults match configs.js: every helper supports
    // cipher / curve selection unless explicitly opted out, and supportsPq
    // defaults to FALSE — only helpers with a PQ codepath today (caddy,
    // gnutls, go, opensslcnf, rust, s2n, traefik) opt in via configs.js.
    supportsCipherSelection: true,
    supportsCurveSelection: true,
    supportsPq: false,

    pqMode: 'none',
  }, overrides);
}

export function makeForm(overrides = {}) {
  return Object.assign({
    config: 'intermediate',
    // serverVersion is intentionally left as the "latest" placeholder; each
    // harness invocation supplies a realistic per-helper value.
    serverVersion: '999.0.0',
    opensslVersion: '3.0.0',
    hsts: false,
    ocsp: false,
    pq: 'none',
  }, overrides);
}

// Re-export node:test so test files can do a one-stop import if desired.
export { test };
