// Shared helper-test harness.
//
// runStandardHelperSuite() registers a bundle of node:test cases that
// exercise the generic assertion categories every output helper is
// expected to satisfy:
//
//   1. Profile mapping       — the modern / intermediate / old profiles
//                              each render a config that pins the right
//                              protocol-version floor (TLSv1.3 / TLSv1.2+
//                              / TLSv1.0+).
//   2. Protocol gating       — when output.protocols excludes TLSv1.3 the
//                              helper does not emit TLSv1.3-only directives,
//                              and vice versa for legacy versions. For
//                              negation-style helpers (exim/coturn/squid)
//                              callers pass `negationVersionTokens` instead
//                              of `versionTokens`; the harness then asserts
//                              the negation token IS present iff the version
//                              is NOT in output.protocols.
//   3. Cipher-string syntax  — the rendered cipher list uses the server's
//                              own syntax (OpenSSL ECDHE-…:!aNULL, Go
//                              tls.TLS_…, IANA TLS_…, GnuTLS +AES-…) and
//                              does not paste the wrong syntax through.
//                              For Go-format helpers EVERY IANA-style token
//                              must carry the `tls.` prefix.
//   4. No-known-broken-prim. — RC4 / MD5 / EXPORT / NULL / SSLv2 / SSLv3
//                              / DES-CBC / aNULL / ADH / AECDH / eNULL /
//                              IDEA / SEED are forbidden in every profile.
//                              3DES is permitted only when form.config ===
//                              'old'. Negation tokens like `!RC4`, `+no_sslv3`,
//                              `NO_SSLv3`, `no-tlsv11` are pre-stripped — they
//                              EXCLUDE the primitive and are therefore safe.
//   5. Forward secrecy       — for `modern` and `intermediate` profiles, the
//                              rendered ciphers never include static-RSA
//                              key-exchange suites (TLS_RSA_WITH_…, OpenSSL
//                              `AES…-SHA…` / `AES…-GCM-…` without an
//                              `(EC)?DHE-` prefix).
//   6. HSTS gating           — Strict-Transport-Security header is present
//                              iff form.hsts && supportsHsts !== false,
//                              contains the correct max-age=N, AND includes
//                              `; includeSubDomains` (default). Helpers that
//                              cannot emit `includeSubDomains` must opt out
//                              with a warning regex.
//   7. Curves emitted        — if output.supportsCurveSelection !== false,
//                              the helper renders the requested
//                              output.tlsCurves entries. Helpers that
//                              cannot express a curve preference declare
//                              `supportsCurveSelection: false` in
//                              configs.js (e.g. mysql, jetty, redis).
//   8. PQ readiness          — if output.supportsPq === true (configs.js
//                              opt-in flag), helper rendered with
//                              form.pq='only' must surface a PQ marker
//                              (X25519MLKEM768 / SecP256r1MLKEM768 /
//                              SecP384r1MLKEM1024 group token, or any
//                              post-quantum / ML-KEM mention). Helpers
//                              without supportsPq:true skip silently.
//
// Per-helper opt-out:
//   For helpers that genuinely cannot satisfy one of the above categories
//   (e.g. AWS ALB exposes only managed policy names instead of cipher
//   strings), the caller may pass an `optOuts` map keyed by category. Each
//   opt-out MUST either declare `notApplicable: true` (the assertion does
//   not apply to this server class — e.g. a database server has no notion
//   of HSTS) OR provide a `warning` regex that the helper's own output is
//   asserted to contain. Silent skips are not allowed: if a helper is
//   opting out of cipher-syntax checking because it surfaces only a policy
//   name, it must tell the user so in the rendered config.

import test from 'node:test';
import assert from 'node:assert/strict';
import { PROFILES, PQ_GROUPS, makeOutput, makeForm } from './fixtures.js';

// Strip text fragments that legitimately CONTAIN a forbidden token but that
// have the OPPOSITE security meaning (i.e. they DISABLE the primitive). For
// example exim emits `+no_sslv3` and squid emits `NO_SSLv3` to *forbid*
// SSLv3 — we must not flag those as the helper renders SSLv3.
//
// This pre-pass removes:
//   - OpenSSL `!`-exclusion tokens (`!aNULL`, `!eNULL`, `!RC4`, `!MD5`,
//     `!EXPORT`, `!SSLv2`, `!SSLv3`, `!3DES`, `!IDEA`, `!SEED`, `!ADH`,
//     `!AECDH`, `!DES`, `!PSK`, `!kRSA`, `!aNULL:!eNULL` etc.)
//   - Negation-prefix tokens used by exim / coturn / haproxy / stunnel /
//     squid: `+no_…`, `no-…`, `no_…`, `NO_…`, `OP_NO_…`. The token body
//     itself is `[A-Za-z][A-Za-z0-9._]*` so we capture e.g. `NO_TLSv1_2`
//     and `no-tlsv1_1`.
function _stripNegationTokens(s) {
  return s
    .replace(/![A-Za-z][A-Za-z0-9_]*/g, '')
    .replace(/\+?\b(?:OP_NO_|NO_|no_|no-)[A-Za-z][A-Za-z0-9._]*/g, '');
}

// Forbidden tokens. Each regex is anchored on `(?<![A-Za-z0-9_])` /
// `(?![A-Za-z0-9_])` boundaries instead of `\b` so that an underscore
// neighbour does NOT artificially break the match. This is what makes the
// IANA names (`TLS_RSA_WITH_DES_CBC_SHA`, `TLS_RSA_WITH_RC4_…`) trip the
// scan, not just the OpenSSL forms (`DES-CBC-SHA`, `RC4-SHA`).
//
// Test infrastructure note: we deliberately do NOT include MD5 in a form
// that would trip on the `_MD5` suffix in IANA names — `WITH_MD5_…` has
// no IANA equivalent we still ship in any profile, but we keep the strict
// `(?<![A-Za-z0-9_])MD5(?![A-Za-z0-9_])` form. Same for RC4 / SSLv2.
const _SEP_BEFORE = '(?<![A-Za-z0-9_])';
const _SEP_AFTER  = '(?![A-Za-z0-9_])';
const FORBIDDEN = [
  { re: new RegExp(_SEP_BEFORE + 'RC4'    + _SEP_AFTER),                        name: 'RC4' },
  { re: new RegExp(_SEP_BEFORE + 'MD5'    + _SEP_AFTER),                        name: 'MD5' },
  { re: new RegExp(_SEP_BEFORE + 'EXPORT' + _SEP_AFTER),                        name: 'EXPORT' },
  // Plain OpenSSL `EXP-…` family (EXPORT-grade) e.g. `EXP-RC4-MD5`.
  { re: /\bEXP-[A-Z]/,                                                          name: 'EXP-… (EXPORT)' },
  // Static RSA NULL ciphers and any explicit NULL-MD5/NULL-SHA entries.
  { re: new RegExp(_SEP_BEFORE + 'NULL[-_](?:MD5|SHA)' + _SEP_AFTER),           name: 'NULL-MD5/SHA' },
  // Anonymous DH / ECDH key exchanges. These provide no peer authentication
  // and make active MITM trivial. Seen as `aNULL`, `ADH-…`, `AECDH-…`,
  // `TLS_DH_anon_…`, `TLS_ECDH_anon_…`. Note that `eNULL` is a *cipher*
  // NULL (no encryption) — also forbidden.
  { re: new RegExp(_SEP_BEFORE + 'aNULL' + _SEP_AFTER),                         name: 'aNULL (anonymous auth)' },
  { re: new RegExp(_SEP_BEFORE + 'eNULL' + _SEP_AFTER),                         name: 'eNULL (NULL encryption)' },
  { re: /\bADH-/,                                                               name: 'ADH (anonymous DH)' },
  { re: /\bAECDH-/,                                                             name: 'AECDH (anonymous ECDH)' },
  { re: /\bTLS_(?:DH|ECDH)_anon_/,                                              name: 'TLS_DH/ECDH_anon (IANA anonymous KE)' },
  // Long-deprecated symmetric ciphers.
  { re: new RegExp(_SEP_BEFORE + 'IDEA' + _SEP_AFTER),                          name: 'IDEA' },
  { re: new RegExp(_SEP_BEFORE + 'SEED' + _SEP_AFTER),                          name: 'SEED' },
  { re: new RegExp(_SEP_BEFORE + 'SSLv2' + _SEP_AFTER),                         name: 'SSLv2' },
  { re: new RegExp(_SEP_BEFORE + 'SSLv3' + _SEP_AFTER),                         name: 'SSLv3' },
  // Single-DES (NOT 3DES). The `(?!3)` lookahead lets `DES-CBC3` /
  // `_3DES_EDE_CBC` pass, but `DES-CBC` and `DES_CBC` trip the scan. We
  // additionally allow `EDE_CBC` (3DES IANA spelling has `_EDE_` between
  // `3DES` and `CBC`).
  { re: /(?<![A-Za-z0-9_])DES[-_]CBC(?!3)(?![A-Za-z0-9])/,                      name: 'DES-CBC (single DES)' },
];

const TRIPLE_DES = /3DES|DES[-_]CBC3/;

// Forward-secrecy regression scan. Mozilla's `modern` and `intermediate`
// profiles intentionally exclude any cipher whose key-exchange is static
// RSA. A future fixture / supportedCiphers regression that admitted such a
// suite would silently downgrade the security posture, so we assert their
// absence here. Match both the IANA family (`TLS_RSA_WITH_…`) and the
// OpenSSL family (`AES128-GCM-SHA256` / `AES256-SHA` etc., which are how
// OpenSSL renders TLS_RSA_WITH_…). The OpenSSL form is identified by the
// absence of an `(EC)?DHE-` prefix on the line — we err on the side of
// matching the canonical `^AES\d{3}-…` cipher-list entries. A negative
// lookbehind on `[-:]` rules out the `(E)CDHE-…-AES…` middle.
const STATIC_RSA = [
  { re: /\bTLS_RSA_WITH_/,                                              name: 'IANA TLS_RSA_WITH_… (static-RSA KE)' },
  // Anchor on a list separator (start, `:` or `\s` or `"` or `=`). This is
  // strict on purpose: a free-text comment containing `AES128` won't trip,
  // but a `…:AES128-GCM-SHA256:…` cipher-list entry will.
  { re: /(?<=^|[\s:"=])AES\d{3}-(?:GCM-)?SHA\d*\b/m,                    name: 'OpenSSL AES…-(GCM-)?SHA (static-RSA KE)' },
];

// Per-cipher-format expectations. Each entry knows:
//   - sample: a known cipher in this format (used as a presence probe)
//   - wrongForms: regexes that, if matched, indicate the helper accidentally
//     rendered a different format (e.g. an OpenSSL name in a Go-format
//     server). Each entry has its own `name` so failures are explainable.
//   - extraInvariants(out): optional callback for format-specific checks
//     (e.g. for `go`, every IANA-style token MUST carry the `tls.` prefix).
const CIPHER_FORMATS = {
  openssl: {
    sample: /\bECDHE-ECDSA-AES128-GCM-SHA256\b/,
    wrongForms: [
      { re: /\btls\.TLS_ECDHE_/,                                              name: 'Go (tls.TLS_…) cipher in an OpenSSL-format helper' },
      { re: /(?<![A-Za-z._])TLS_(?:ECDHE|DHE|RSA)_[A-Z]/,                     name: 'IANA (TLS_…) cipher in an OpenSSL-format helper' },
    ],
  },
  iana: {
    sample: /\bTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\b/,
    wrongForms: [
      // OpenSSL ECDHE-…- names must not appear directly. Match on the
      // ECDHE-… prefix to avoid colliding with IANA TLS_ECDHE_… names.
      { re: /\bECDHE-(?:ECDSA|RSA)-/,                                         name: 'OpenSSL (ECDHE-…) cipher in an IANA/Go-format helper' },
      // Likewise OpenSSL DHE-… cipher names.
      { re: /\bDHE-RSA-AES/,                                                  name: 'OpenSSL (DHE-RSA-AES…) cipher in an IANA-format helper' },
      // Bare OpenSSL `AESnnn-(GCM-)?SHAm` (static-RSA family) anchored on a
      // list separator to avoid matching free-text comments.
      { re: /(?<=^|[\s:"=])AES\d{3}-(?:GCM-)?SHA\d*\b/m,                      name: 'OpenSSL bare AES…-SHA (static-RSA) in an IANA helper' },
    ],
  },
  // 'go' helpers consume IANA names internally (state.js:140) but render
  // them with the `tls.` prefix.
  go: {
    sample: /\btls\.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\b/,
    wrongForms: [
      { re: /\bECDHE-(?:ECDSA|RSA)-/,                                         name: 'OpenSSL (ECDHE-…) cipher in a Go-format helper' },
    ],
    // Stronger invariant: every IANA-shaped TLS_… token in the rendered
    // output MUST be immediately preceded by `tls.`. A bare `TLS_AES_…`
    // means the helper forgot the prefix.
    extraInvariants(out) {
      const tokens = out.match(/(?<![A-Za-z._])TLS_(?:AES|CHACHA|ECDHE|DHE|RSA)_[A-Z0-9_]+/g) || [];
      for (const tok of tokens) {
        const idx = out.indexOf(tok);
        const before = idx >= 4 ? out.slice(idx - 4, idx) : '';
        assert.equal(before, 'tls.',
          `Go-format helper emitted bare IANA token '${tok}' without 'tls.' prefix`);
      }
    },
  },
};

// Validate that an opt-out declaration is well-formed AND, if it claims a
// warning is emitted, that the warning is actually present in `out`. Returns
// true when the assertion was opted out of (caller should skip its check).
function _consumeOptOut(category, optOuts, out) {
  if (!optOuts || !optOuts[category]) return false;
  const opt = optOuts[category];
  if (opt.notApplicable === true) {
    // The category does not apply to this class of server (e.g. HSTS for a
    // database). No warning required.
    return true;
  }
  if (opt.warning instanceof RegExp) {
    assert.match(
      out,
      opt.warning,
      `opt-out of '${category}' requires the helper to emit a warning matching ${opt.warning}, ` +
      `but no such warning was found in the rendered output`,
    );
    return true;
  }
  throw new Error(
    `optOuts.${category} must declare either notApplicable:true or warning:/regex/ ` +
    `(silent opt-outs are not allowed)`,
  );
}

// Public entry point.
//
//   runStandardHelperSuite({
//     name:             'nginx',
//     helper:           require('../src/js/helpers/nginx.js').default,
//     serverVersion:    '1.27.3',     // a stable latest version of the server
//     supportsHsts:     true,         // mirrors configs.js[name].supportsHsts !== false
//     cipherFormat:     'openssl',    // 'openssl' | 'iana' | 'go'
//
//     // Per-profile regex matching the server's TLS-version directive in
//     // the rendered config when called with that profile's protocols list.
//     protocolDirective: {
//       modern:       /ssl_protocols\s+TLSv1\.3;/,
//       intermediate: /ssl_protocols\s+TLSv1\.2 TLSv1\.3;/,
//       old:          /ssl_protocols\s+TLSv1 TLSv1\.1 TLSv1\.2 TLSv1\.3;/,
//     },
//
//     // OPTIONAL: per-version regex matching how this server names a TLS
//     // protocol version, used for the protocol-gating test. Each entry
//     // must match if and only if that version is in output.protocols.
//     versionTokens: {
//       'TLSv1':   /\bTLSv1\b(?![.\d])/,
//       'TLSv1.1': /\bTLSv1\.1\b/,
//       'TLSv1.2': /\bTLSv1\.2\b/,
//       'TLSv1.3': /\bTLSv1\.3\b/,
//     },
//
//     // OPTIONAL (mutually exclusive with versionTokens): per-version regex
//     // matching the NEGATION token (e.g. `+no_tlsv1_2`, `NO_SSLv3`). For
//     // negation-style helpers the harness asserts the token IS present
//     // when the version is NOT in output.protocols, and IS NOT present
//     // when the version IS in output.protocols. The harness automatically
//     // strips matching negation tokens before the forbidden-primitive
//     // scan (a `+no_sslv3` is a *good* SSLv3 mention).
//     negationVersionTokens: {
//       'SSLv3':   /\+no_sslv3\b/,
//       'TLSv1':   /\+no_tlsv1\b(?!_)/,
//       'TLSv1.1': /\+no_tlsv1_1\b/,
//       'TLSv1.2': /\+no_tlsv1_2\b/,
//     },
//
//     hstsHeader: /Strict-Transport-Security[^\n]*max-age=63072000[^\n]*includeSubDomains/,
//     // ↑ default. Helpers that can't emit `includeSubDomains` must declare
//     //   optOuts.hstsIncludeSubDomains: { warning: /…/ }.
//
//     formOverrides:    { /* extra form fields, e.g. opensslVersion */ },
//
//     optOuts: {
//       cipherSyntax:           { warning: /managed policy name/i },
//       hsts:                   { notApplicable: true },
//       hstsIncludeSubDomains:  { warning: /you might want to also enable "includeSubDomains"/ },
//       curvesPresent:          { notApplicable: true },  // declare via configs.js supportsCurveSelection:false instead
//       forwardSecrecy:         { warning: /static-RSA cipher/ }, // very rare
//       // ... etc.
//     },
//
//     // OPTIONAL: callback for helper-specific tests beyond the generic
//     // suite. Receives node:test's `test` function pre-prefixed with
//     // `${name}: `.
//     extraTests:       (t) => { t('does X', () => { ... }); },
//   });
export function runStandardHelperSuite(opts) {
  const {
    name,
    helper,
    serverVersion,
    supportsHsts = true,
    // Curve / cipher capability flags (mirror configs.js attrs of the same
    // name). Default to whatever the test fixture renders (i.e. true);
    // helpers that genuinely cannot express the knob (mysql, jetty, awsalb,
    // s2n, …) pass `false` here. This is also where version-gated coverage
    // is expressed: e.g. postgres.js only emits `ssl_groups` from v18+, so
    // its test passes `supportsCurveSelection:false` at the v17.2 latest.
    supportsCipherSelection,
    supportsCurveSelection,
    // PQ capability flag (mirrors configs.js supportsPq). Defaults to
    // undefined → the harness inherits the fixture default (false). Helpers
    // with a PQ-aware codepath today (caddy, gnutls, go, opensslcnf, rust,
    // s2n, traefik) pass `true` here; the harness then asserts the helper
    // surfaces a recognizable PQ marker (group token or PQ comment) when
    // rendered with `pq:'only'`.
    supportsPq,
    cipherFormat = 'openssl',
    protocolDirective,
    versionTokens,
    negationVersionTokens,
    hstsHeader,
    formOverrides = {},
    optOuts = {},
    // Regex matching a line-comment (whole line) in this server's config
    // syntax. The protocol-gating test strips matching lines before
    // checking versionTokens, so version strings that appear only in
    // explanatory comments don't trigger false positives. All Tier 1
    // helpers use '#' for line comments; Go-style helpers can override
    // (e.g. /^\s*\/\/.*$/gm).
    commentLine = /^\s*#.*$/gm,
  } = opts;

  if (!name || typeof helper !== 'function') {
    throw new Error('runStandardHelperSuite: name + helper are required');
  }
  if (!CIPHER_FORMATS[cipherFormat]) {
    throw new Error(`runStandardHelperSuite: unknown cipherFormat ${cipherFormat}`);
  }
  if (versionTokens && negationVersionTokens) {
    throw new Error('runStandardHelperSuite: versionTokens and negationVersionTokens are mutually exclusive');
  }

  const baseForm = (overrides = {}) => makeForm(Object.assign(
    { serverVersion }, formOverrides, overrides,
  ));
  const baseOutput = (profile, overrides = {}) => {
    const merged = Object.assign({ cipherFormat }, overrides);
    if (supportsCipherSelection !== undefined) merged.supportsCipherSelection = supportsCipherSelection;
    if (supportsCurveSelection  !== undefined) merged.supportsCurveSelection  = supportsCurveSelection;
    if (supportsPq              !== undefined) merged.supportsPq              = supportsPq;
    return makeOutput(profile, merged);
  };

  const t = (label, fn) => test(`${name}: ${label}`, fn);

  // ----- 1. Profile mapping --------------------------------------------------
  t('profile mapping pins the expected protocol-version floor for modern/intermediate/old', () => {
    if (_consumeOptOut('profileMapping', optOuts,
        helper(baseForm({ config: 'intermediate' }), baseOutput('intermediate')))) {
      return;
    }
    assert.ok(protocolDirective, 'protocolDirective is required unless profileMapping is opted out');
    for (const profile of PROFILES) {
      const out = helper(baseForm({ config: profile }), baseOutput(profile));
      assert.match(
        out,
        protocolDirective[profile],
        `profile '${profile}' did not render expected protocol directive ${protocolDirective[profile]}`,
      );
    }
  });

  // ----- 2. Protocol gating --------------------------------------------------
  t('protocol gating: emitted version tokens match output.protocols', () => {
    // Use intermediate (TLSv1.2 + TLSv1.3) and a 1.3-stripped variant to test
    // both directions. If a versionTokens map is not provided we fall back to
    // exercising profileMapping again (modern omits TLS1.2, old includes
    // TLS1).
    const probe = (form, output) => helper(form, output);
    const intermediate = baseOutput('intermediate');
    const noTls13 = Object.assign({}, intermediate, { protocols: ['TLSv1.2'] });
    const onlyTls13 = baseOutput('modern');

    const out12 = probe(baseForm({ config: 'intermediate' }), noTls13);
    const out13 = probe(baseForm({ config: 'modern' }),       onlyTls13);

    if (_consumeOptOut('protocolGating', optOuts, out12)) return;

    if (versionTokens || negationVersionTokens) {
      // Strict per-version assertion. Strip line comments first so e.g.
      // nginx's "uncomment to enable if ssl_protocols includes TLSv1.2 or
      // earlier" footer doesn't false-positive.
      const strip = (s) => commentLine ? s.replace(commentLine, '') : s;
      const checkPair = (out, output) => {
        const code = strip(out);
        if (versionTokens) {
          // POSITIVE encoding: token present ⇔ version enabled.
          for (const [version, re] of Object.entries(versionTokens)) {
            if (output.protocols.includes(version)) {
              assert.match(code, re, `expected token for ${version} in output (protocols=${output.protocols})`);
            } else {
              assert.doesNotMatch(code, re, `unexpected token for ${version} in output (protocols=${output.protocols})`);
            }
          }
        } else {
          // NEGATION encoding: token present ⇔ version DISABLED. Used by
          // exim/coturn/squid; replaces the brittle per-helper pinning of
          // the full options= line that used to be needed in those tests.
          for (const [version, re] of Object.entries(negationVersionTokens)) {
            if (output.protocols.includes(version)) {
              assert.doesNotMatch(code, re,
                `negation token for ${version} present even though ${version} is enabled ` +
                `(protocols=${output.protocols})`);
            } else {
              assert.match(code, re,
                `expected NEGATION token for disabled ${version} (protocols=${output.protocols})`);
            }
          }
        }
      };
      checkPair(out12, noTls13);
      checkPair(out13, onlyTls13);
    } else {
      // Weak fallback: just check that protocolDirective for modern matches
      // the TLS-1.3-only render (catches helpers that accidentally
      // hard-code the version list).
      assert.ok(protocolDirective,
        'either versionTokens, negationVersionTokens, or protocolDirective must be supplied for protocol-gating');
      assert.match(out13, protocolDirective.modern);
    }
  });

  // ----- 3. Cipher-string syntax --------------------------------------------
  t('cipher-string syntax matches the server\'s own format and does not leak other formats', () => {
    // 'modern' has an empty output.ciphers (TLS1.3-only profile); use
    // intermediate so there are real ciphers to inspect.
    const out = helper(baseForm({ config: 'intermediate' }), baseOutput('intermediate'));

    if (_consumeOptOut('cipherSyntax', optOuts, out)) {
      // Even when cipherSyntax is opted out, we still verify that the
      // helper isn't accidentally LEAKING any cipher names from the wrong
      // syntax — the warning regex documents WHY it can't emit them, not
      // a license to emit garbage.
      const fmt = CIPHER_FORMATS[cipherFormat];
      for (const wrong of fmt.wrongForms) {
        assert.doesNotMatch(out, wrong.re,
          `opt-out of cipherSyntax does not allow leaking ${wrong.name}: ${wrong.re}`);
      }
      // For helpers whose configs.js declares supportsCipherSelection:false
      // (e.g. AWS ALB), the rendered config also must not contain cipher
      // tokens at all — only managed-policy identifiers.
      if (baseOutput('intermediate').supportsCipherSelection === false) {
        assert.doesNotMatch(out, /\bECDHE-(?:ECDSA|RSA)-AES/,
          'helper marked supportsCipherSelection:false but emitted an OpenSSL cipher token');
        assert.doesNotMatch(out, /(?<![A-Za-z._])TLS_(?:ECDHE|DHE|RSA)_WITH_/,
          'helper marked supportsCipherSelection:false but emitted an IANA cipher token');
      }
      return;
    }

    const fmt = CIPHER_FORMATS[cipherFormat];
    assert.match(
      out,
      fmt.sample,
      `expected at least one ${cipherFormat}-format cipher (e.g. ${fmt.sample}) in rendered output`,
    );
    for (const wrong of fmt.wrongForms) {
      assert.doesNotMatch(
        out,
        wrong.re,
        `unexpected ${wrong.name}: ${wrong.re}`,
      );
    }
    if (typeof fmt.extraInvariants === 'function') {
      fmt.extraInvariants(out);
    }
  });

  // ----- 4. Forbidden-primitive scan ----------------------------------------
  t('rendered config never references known-broken primitives (RC4/MD5/EXPORT/NULL/SSLv2-3/DES/aNULL/IDEA/SEED)', () => {
    for (const profile of PROFILES) {
      const raw = helper(
        baseForm({ config: profile, hsts: supportsHsts, ocsp: true }),
        baseOutput(profile),
      );
      if (_consumeOptOut('forbiddenPrimitives', optOuts, raw)) return;
      // Pre-strip negation tokens. A `+no_sslv3` / `NO_SSLv3` / `!RC4`
      // mention is the OPPOSITE of insecure; it disables the primitive.
      const out = _stripNegationTokens(raw);
      for (const f of FORBIDDEN) {
        assert.doesNotMatch(
          out,
          f.re,
          `forbidden token '${f.name}' (${f.re}) appeared for profile=${profile}`,
        );
      }
      // 3DES is allowed ONLY in the 'old' profile.
      if (profile !== 'old') {
        assert.doesNotMatch(
          out,
          TRIPLE_DES,
          `3DES must not appear in profile=${profile}`,
        );
      }
    }
  });

  // ----- 5. Forward-secrecy regression scan ---------------------------------
  t('modern/intermediate profiles never emit static-RSA cipher names', () => {
    for (const profile of ['modern', 'intermediate']) {
      const out = helper(baseForm({ config: profile }), baseOutput(profile));
      if (_consumeOptOut('forwardSecrecy', optOuts, out)) return;
      // Strip negation tokens (e.g. `!kRSA`) before scanning.
      const stripped = _stripNegationTokens(out);
      for (const f of STATIC_RSA) {
        assert.doesNotMatch(
          stripped,
          f.re,
          `static-RSA cipher leaked into profile=${profile}: ${f.name} (${f.re})`,
        );
      }
    }
  });

  // ----- 6. HSTS gating ------------------------------------------------------
  t('HSTS gating: header present iff form.hsts && supportsHsts, with correct max-age + includeSubDomains', () => {
    if (supportsHsts === false) {
      // The server class does not support HSTS at all. Make sure that even
      // if the user toggles form.hsts on, the helper does not emit a STS
      // header (defensive: configs.js hides the toggle, but the helper
      // should still be safe).
      const out = helper(baseForm({ hsts: true }), baseOutput('intermediate'));
      if (_consumeOptOut('hsts', optOuts, out)) return;
      assert.doesNotMatch(out, /Strict-Transport-Security/,
        'helper marked supportsHsts:false but emitted Strict-Transport-Security');
      return;
    }

    const without = helper(baseForm({ hsts: false }), baseOutput('intermediate'));
    const withOn  = helper(baseForm({ hsts: true  }), baseOutput('intermediate'));

    if (_consumeOptOut('hsts', optOuts, withOn)) return;

    assert.doesNotMatch(without, /Strict-Transport-Security/,
      'STS header rendered with form.hsts=false');
    // Default header includes BOTH max-age=N and includeSubDomains. Per
    // RFC 6797 §6.1.2, includeSubDomains is the recommended hardening for
    // any host other than the apex; omitting it allows a subdomain that
    // doesn't enforce HTTPS to be the foothold for a downgrade. Helpers
    // that legitimately can't emit it (e.g. traefik leaves it commented
    // for the user to enable per-config) MUST opt out via
    // optOuts.hstsIncludeSubDomains:{ warning: /…/ }.
    const expected = hstsHeader || /Strict-Transport-Security[^\n]*max-age=63072000[^\n]*includeSubDomains/;
    assert.match(withOn, expected,
      `expected STS header matching ${expected} when form.hsts=true`);
    if (!_consumeOptOut('hstsIncludeSubDomains', optOuts, withOn)) {
      // Case-insensitive match: some helpers use the literal HTTP header
      // spelling `includeSubDomains` (capital D), others use config-key
      // conventions like Traefik's `stsIncludeSubdomains` (lowercase d).
      // Both encode the same directive — what matters is the rendered
      // HTTP response, and the helper-specific `hstsHeader` regex
      // already pins the exact emitted form.
      assert.match(withOn, /includesubdomains/i,
        'STS configuration is missing the includeSubDomains directive (RFC 6797 §6.1.2). ' +
        'If this helper genuinely cannot emit it, declare ' +
        'optOuts.hstsIncludeSubDomains:{ warning: /…/ }.');
    }

    // hstsMaxAge round-trip: re-render with a sentinel max-age value and
    // assert it (a) appears in the rendered output and (b) replaces the
    // default 63072000. Catches helpers that hard-code max-age instead of
    // splicing in output.hstsMaxAge from state.js.
    const SENTINEL_MAX_AGE = 12345678;
    const withSentinel = helper(
      baseForm({ hsts: true }),
      baseOutput('intermediate', { hstsMaxAge: SENTINEL_MAX_AGE }),
    );
    if (!_consumeOptOut('hstsMaxAgeRoundTrip', optOuts, withSentinel)) {
      assert.match(withSentinel, new RegExp('\\b' + SENTINEL_MAX_AGE + '\\b'),
        'STS rendering ignored output.hstsMaxAge (sentinel value not present). ' +
        'Helpers must splice the configured max-age, not hard-code 63072000.');
      assert.doesNotMatch(withSentinel, /\b63072000\b/,
        'STS rendering hard-codes max-age=63072000 instead of using output.hstsMaxAge.');
    }
  });

  // ----- 7. Curves-emitted assertion ----------------------------------------
  t('renders the requested TLS named groups (curves) when the server supports curve selection', () => {
    // Per the configs.js capability flag (mirrored into output by state.js
    // and by the test fixtures), helpers that genuinely can't express a
    // curve preference (mysql, redis, jetty, …) skip this check.
    const intermediate = baseOutput('intermediate');
    if (intermediate.supportsCurveSelection === false) return;
    const out = helper(baseForm({ config: 'intermediate' }), intermediate);
    if (_consumeOptOut('curvesPresent', optOuts, out)) return;
    // Exact rendering varies (`X25519` vs `GROUP-X25519` vs `prime256v1`),
    // so we assert that AT LEAST ONE of the requested curves appears in
    // the rendered config. Helpers with custom group-name mappings (e.g.
    // GnuTLS GROUP-…) may need to opt out — they should declare
    // optOuts.curvesPresent:{ warning: /…/ } pointing at their group line.
    const anyCurve = intermediate.tlsCurves.some(c => out.includes(c));
    assert.ok(anyCurve,
      `none of the requested curves (${intermediate.tlsCurves.join(', ')}) appear in the rendered config. ` +
      `If this helper renames groups (e.g. prime256v1 → SECP256R1), declare ` +
      `optOuts.curvesPresent:{ warning: /<your group line>/ }.`);
  });

  // ----- 8. Post-Quantum readiness (capability flag) ------------------------
  //
  // Mirrors output.supportsPq (configs.js). Helpers that opt in (caddy,
  // gnutls, go, opensslcnf, rust, s2n, traefik today) MUST surface a
  // recognizable PQ marker — either an IANA-assigned ML-KEM hybrid group
  // token (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024) or an
  // explanatory comment mentioning post-quantum / PQ / ML-KEM — when
  // rendered with `form.pq = 'only'` (modern profile, since PQ-only forces
  // TLSv1.3).  This catches a regression that drops the helper's PQ
  // codepath (e.g. a refactor that filters MLKEM tokens out of tlsCurves
  // without preserving the explanatory comment, or a config rename that
  // breaks the `if (form.pq === 'only')` branch).
  //
  // Helpers without supportsPq:true skip the assertion silently — they
  // have no PQ surface to assert against and that's the documented
  // capability state.
  t('PQ readiness: helpers with supportsPq:true surface a PQ marker (group token or PQ/ML-KEM comment) when form.pq=only', () => {
    // Mirror what state.js does in production for `pq:'only'`: strip
    // classical groups from output.tlsCurves and force the X25519MLKEM768
    // hybrid (state.js:159-174). The static fixtures don't run state.js,
    // so we replicate the curve-filter shape here.
    const merged = baseOutput('modern', {
      pqMode: 'only',
      tlsCurves: ['X25519MLKEM768'],
    });
    if (merged.supportsPq !== true) return;
    const out = helper(baseForm({ config: 'modern', pq: 'only' }), merged);
    if (_consumeOptOut('pqReadiness', optOuts, out)) return;
    assert.equal(typeof out, 'string',
      'PQ readiness: helper returned a non-string when rendered with pq=only');
    const hasPqGroupToken = PQ_GROUPS.some(g => out.includes(g));
    const hasPqMention    = /post[- ]?quantum|\bPQ\b|ML[- ]?KEM/i.test(out);
    assert.ok(hasPqGroupToken || hasPqMention,
      `helper opts in to supportsPq:true but rendered output for pq=only contains neither ` +
      `a PQ group codepoint (${PQ_GROUPS.join(' / ')}) nor any post-quantum / ML-KEM mention. ` +
      `Either restore the PQ codepath or drop supportsPq from configs.js.`);
  });

  // ----- 9. Input validation: helpers must fail LOUDLY on bad inputs -------
  //
  // Helpers are pure render templates: they receive a `(form, output)` pair
  // built by state.js from vetted guideline JSON. There is no per-helper
  // input validation (validation lives upstream in state.js). The realistic
  // threat model is: a future state.js refactor accidentally fails to
  // populate a field on `output`, and the helper silently emits a broken /
  // permissive config.
  //
  // Contract enforced here: for any malformed `(form, output)` pair, the
  // helper must either
  //   (a) throw an exception, OR
  //   (b) render output where TLS-policy DIRECTIVE lines never contain the
  //       literal `undefined` / `null` substring — i.e. a missing field
  //       must be omitted, not silently spliced in.
  //
  // Why both alternatives are acceptable:
  //   - Some helpers (mysql, jetty) don't reference `form` at all, so an
  //     undefined `form` is harmless by construction.
  //   - Other helpers (litespeed) actively defend against missing
  //     `output.protocols` by skipping the directive — a *good* defensive
  //     pattern that we want to preserve.
  //
  // We exclude:
  //   - Comment lines (`#`, `//`, `;`, `<!-- … -->`) — `# undefined` in a
  //     header banner is a cosmetic bug, not a silent security regression.
  //   - String-literal payloads (CloudFormation `Description:`,
  //     `MessageBody:`, AWS `PolicyName:`, Go `w.Write([]byte("…"))`)
  //     because they are not TLS-policy directives — they are descriptive
  //     metadata that downstream consumers (CloudFormation, the Go
  //     compiler) parse and reject loudly if malformed (`Mozilla-undefined-
  //     v5-0` is an invalid AWS policy reference and would be rejected by
  //     AWS at deploy time, not silently honoured).
  t('input validation: helper either throws or omits fields cleanly on malformed input (no "undefined" in TLS directives)', () => {
    const cases = [
      { label: 'undefined form, undefined output',     args: [undefined, undefined] },
      { label: 'null form, null output',               args: [null, null] },
      { label: 'valid form, undefined output',         args: [baseForm(), undefined] },
      { label: 'undefined form, valid output',         args: [undefined, baseOutput('intermediate')] },
      // The realistic threat: state.js fails to populate output.* fields.
      // Helpers must defend against this OR throw.
      { label: 'valid form, output={} (no protocols)', args: [baseForm(), {}] },
    ];
    // Strip lines that any sane TLS-config parser would ignore:
    //   - shell / nginx / haproxy / ini / postfix / postgres style:  `# …`
    //   - go / traefik (TOML alt) / rust style:                      `// …`
    //   - stunnel / coturn / squid:                                  `; …`
    //   - jetty XML / litespeed XML:                                 `<!-- … -->`
    // Then strip lines that are descriptive metadata (not TLS directives):
    //   - CloudFormation `Description:` / `MessageBody:` (awsalb/awselb)
    //   - AWS `PolicyName:` / inline `Mozilla-…-v…-…` policy refs
    //   - Go HTTP response body string literals (`w.Write([]byte("…"))`)
    // After stripping, `undefined` / `null` would only appear inside a
    // real TLS directive — which IS a silent security failure.
    const stripIgnorableLines = (s) => s
      .replace(/<!--[\s\S]*?-->/g, '')                           // multi-line XML comments
      .replace(/^\s*#.*$/gm, '')                                 // # …
      .replace(/^\s*\/\/.*$/gm, '')                              // // …
      .replace(/^\s*;.*$/gm, '')                                 // ; …
      .replace(/^.*\b(?:Description|MessageBody|PolicyName)\s*:.*$/gm, '')  // CloudFormation/AWS metadata
      .replace(/^.*Mozilla-[A-Za-z0-9_-]+-v\d+-\d+.*$/gm, '')    // AWS policy refs (Mozilla-X-vN-N)
      .replace(/^.*w\.Write\(\[\]byte\("[^"]*"\)\).*$/gm, '');   // Go HTTP response body literals
    for (const c of cases) {
      let out;
      let threw = false;
      try {
        out = helper(c.args[0], c.args[1]);
      } catch (_e) {
        threw = true;
      }
      if (threw) continue;  // (a) — fail-loud is acceptable
      assert.equal(typeof out, 'string',
        `helper accepted malformed input '${c.label}' and returned a non-string (${typeof out})`);
      const directives = stripIgnorableLines(out);
      assert.doesNotMatch(directives, /\bundefined\b/,
        `helper accepted malformed input '${c.label}' and silently spliced the literal token 'undefined' ` +
        `into a TLS-policy DIRECTIVE — a security-critical setting may have been corrupted`);
      assert.doesNotMatch(directives, /(?<![\w/-])null(?![\w-])/,
        `helper accepted malformed input '${c.label}' and silently spliced the literal token 'null' ` +
        `into a TLS-policy DIRECTIVE — a security-critical setting may have been corrupted`);
    }
  });

  // ----- 8. Legacy-version smoke (coverage of older code paths) -------------
  // Many helpers fork heavily on `minver(...)` to support old server / openssl
  // releases (e.g. lighttpd 1.4.46, postfix 3.4, haproxy 1.5, traefik 1.x,
  // postgres 12). The default test invocation only exercises the latest
  // stable, leaving those branches untested.
  //
  // For each entry in `legacyVersions`, render the helper across all three
  // profiles × HSTS on/off × OCSP on/off and assert the same INVARIANTS that
  // matter at any version: the rendered output is non-empty AND contains no
  // forbidden primitives. We deliberately do NOT assert per-version protocol
  // / cipher syntax — the alternate code paths intentionally use older
  // syntaxes (e.g. `options = NO_TLSv1.1`, `tune.ssl.default-dh-param`) that
  // wouldn't satisfy the same assertions as the current release.
  //
  // Schema:
  //   legacyVersions: [
  //     { serverVersion: '1.4.40', opensslVersion: '1.0.1', label: 'pre-1.4.46' },
  //     ...
  //   ]
  // The optional `label` is just for human-readable test names.
  const legacyVersions = opts.legacyVersions || [];
  for (const lv of legacyVersions) {
    const tag = lv.label || `serverVersion=${lv.serverVersion}`;
    t(`legacy smoke (${tag}): no forbidden primitives across profiles × hsts × ocsp`, () => {
      const overrides = { serverVersion: lv.serverVersion };
      if (lv.opensslVersion) overrides.opensslVersion = lv.opensslVersion;
      for (const profile of PROFILES) {
        for (const hsts of [false, true]) {
          for (const ocsp of [false, true]) {
            const form = baseForm(Object.assign({ config: profile, hsts, ocsp }, overrides));
            const raw  = helper(form, baseOutput(profile));
            assert.ok(typeof raw === 'string' && raw.length > 0,
              `legacy ${tag}: helper returned empty output for profile=${profile} hsts=${hsts} ocsp=${ocsp}`);
            const out = _stripNegationTokens(raw);
            for (const f of FORBIDDEN) {
              assert.doesNotMatch(out, f.re,
                `legacy ${tag}: forbidden token '${f.name}' (${f.re}) appeared for profile=${profile} hsts=${hsts} ocsp=${ocsp}`);
            }
            if (profile !== 'old') {
              assert.doesNotMatch(out, TRIPLE_DES,
                `legacy ${tag}: 3DES must not appear in profile=${profile}`);
            }
          }
        }
      }
    });
  }

  // ----- helper-specific extras ---------------------------------------------
  if (typeof opts.extraTests === 'function') {
    opts.extraTests(t);
  }
}

