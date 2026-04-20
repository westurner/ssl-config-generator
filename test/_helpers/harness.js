// Shared helper-test harness.
//
// runStandardHelperSuite() registers a bundle of node:test cases that
// exercise the five generic assertion categories every output helper is
// expected to satisfy:
//
//   1. Profile mapping       — the modern / intermediate / old profiles
//                              each render a config that pins the right
//                              protocol-version floor (TLSv1.3 / TLSv1.2+
//                              / TLSv1.0+).
//   2. Protocol gating       — when output.protocols excludes TLSv1.3 the
//                              helper does not emit TLSv1.3-only directives,
//                              and vice versa for legacy versions.
//   3. Cipher-string syntax  — the rendered cipher list uses the server's
//                              own syntax (OpenSSL ECDHE-…:!aNULL, Go
//                              tls.TLS_…, IANA TLS_…, GnuTLS +AES-…) and
//                              does not paste the wrong syntax through.
//   4. No-known-broken-prim. — RC4 / MD5 / EXPORT / NULL-MD5,SHA / SSLv2 /
//                              SSLv3 / DES-CBC are forbidden in every
//                              profile. 3DES is permitted only when
//                              form.config === 'old'.
//   5. HSTS gating           — Strict-Transport-Security header is present
//                              iff form.hsts && supportsHsts !== false,
//                              and contains the correct max-age=N.
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
import { PROFILES, makeOutput, makeForm } from './fixtures.js';

// Forbidden tokens. The DES-CBC pattern matches plain single-DES (with
// either `-` or `_` separator, e.g. OpenSSL DES-CBC-SHA or IANA
// TLS_RSA_WITH_DES_CBC_SHA) but NOT 3DES (DES-CBC3 / 3DES_EDE).
const FORBIDDEN = [
  { re: /\bRC4\b/,                  name: 'RC4' },
  { re: /\bMD5\b/,                  name: 'MD5' },
  { re: /\bEXPORT\b/,               name: 'EXPORT' },
  { re: /\bNULL[-_](?:MD5|SHA)\b/,  name: 'NULL-MD5/SHA' },
  { re: /\bSSLv2\b/,                name: 'SSLv2' },
  { re: /\bSSLv3\b/,                name: 'SSLv3' },
  { re: /\bDES[-_]CBC\b(?!3)/,      name: 'DES-CBC (single DES)' },
];

const TRIPLE_DES = /3DES|DES[-_]CBC3/;

// Per-cipher-format expectations. Each entry knows:
//   - sample: a known cipher in this format (used as a presence probe)
//   - wrongForms: regexes that, if matched, indicate the helper accidentally
//     rendered a different format (e.g. an OpenSSL name in a Go-format
//     server). Each entry has its own `name` so failures are explainable.
const CIPHER_FORMATS = {
  openssl: {
    sample: /\bECDHE-ECDSA-AES128-GCM-SHA256\b/,
    wrongForms: [
      { re: /\btls\.TLS_ECDHE_/,  name: 'Go (tls.TLS_…) cipher in an OpenSSL-format helper' },
    ],
  },
  iana: {
    sample: /\bTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\b/,
    wrongForms: [
      // OpenSSL ECDHE-…- names must not appear directly. Match on the
      // ECDHE-… prefix to avoid colliding with IANA TLS_ECDHE_… names.
      { re: /\bECDHE-(?:ECDSA|RSA)-/,  name: 'OpenSSL (ECDHE-…) cipher in an IANA/Go-format helper' },
    ],
  },
  // 'go' helpers consume IANA names internally (state.js:140) but render
  // them with the `tls.` prefix.
  go: {
    sample: /\btls\.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\b/,
    wrongForms: [
      { re: /\bECDHE-(?:ECDSA|RSA)-/,  name: 'OpenSSL (ECDHE-…) cipher in a Go-format helper' },
    ],
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
//       'TLSv1.3': /\bTLSv1\.3\b/,
//       'TLSv1.2': /\bTLSv1\.2\b/,
//       'TLSv1.1': /\bTLSv1\.1\b/,
//       'TLSv1':   /\bTLSv1\b(?![.\d])/,
//     },
//
//     hstsHeader: /Strict-Transport-Security[^\n]*max-age=63072000/,
//
//     formOverrides:    { /* extra form fields, e.g. opensslVersion */ },
//
//     optOuts: {
//       cipherSyntax:   { warning: /managed policy name/i },
//       hsts:           { notApplicable: true },
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
    cipherFormat = 'openssl',
    protocolDirective,
    versionTokens,
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

  const baseForm = (overrides = {}) => makeForm(Object.assign(
    { serverVersion }, formOverrides, overrides,
  ));
  const baseOutput = (profile, overrides = {}) => makeOutput(
    profile, Object.assign({ cipherFormat }, overrides),
  );

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

    if (versionTokens) {
      // Strict per-version assertion: every requested version must appear,
      // every non-requested version must NOT appear. Strip line comments
      // first so e.g. nginx's "uncomment to enable if ssl_protocols
      // includes TLSv1.2 or earlier" footer doesn't false-positive.
      const strip = (s) => commentLine ? s.replace(commentLine, '') : s;
      const checkPair = (out, output) => {
        const code = strip(out);
        for (const [version, re] of Object.entries(versionTokens)) {
          if (output.protocols.includes(version)) {
            assert.match(code, re, `expected token for ${version} in output (protocols=${output.protocols})`);
          } else {
            assert.doesNotMatch(code, re, `unexpected token for ${version} in output (protocols=${output.protocols})`);
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
        'either versionTokens or protocolDirective must be supplied for protocol-gating');
      assert.match(out13, protocolDirective.modern);
    }
  });

  // ----- 3. Cipher-string syntax --------------------------------------------
  t('cipher-string syntax matches the server\'s own format and does not leak other formats', () => {
    // 'modern' has an empty output.ciphers (TLS1.3-only profile); use
    // intermediate so there are real ciphers to inspect.
    const out = helper(baseForm({ config: 'intermediate' }), baseOutput('intermediate'));

    if (_consumeOptOut('cipherSyntax', optOuts, out)) return;

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
  });

  // ----- 4. Forbidden-primitive scan ----------------------------------------
  t('rendered config never references known-broken primitives (RC4/MD5/EXPORT/NULL/SSLv2-3/DES-CBC)', () => {
    for (const profile of PROFILES) {
      const out = helper(
        baseForm({ config: profile, hsts: supportsHsts, ocsp: true }),
        baseOutput(profile),
      );
      if (_consumeOptOut('forbiddenPrimitives', optOuts, out)) return;
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

  // ----- 5. HSTS gating ------------------------------------------------------
  t('HSTS gating: header present iff form.hsts && supportsHsts, with correct max-age', () => {
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
    const expected = hstsHeader || /Strict-Transport-Security[^\n]*max-age=63072000/;
    assert.match(withOn, expected,
      `expected STS header matching ${expected} when form.hsts=true`);
  });

  // ----- helper-specific extras ---------------------------------------------
  if (typeof opts.extraTests === 'function') {
    opts.extraTests(t);
  }
}
