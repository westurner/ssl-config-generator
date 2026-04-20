// squid helper — generic-suite tests via the shared harness.
//
// Squid selects protocols by NEGATION on the `options=` field:
// `options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET`. A token's PRESENCE
// means the version is EXCLUDED, so per-version gating doesn't directly
// apply — we pin the full options= line per profile. Squid is a caching
// proxy; no HSTS notion.
//
// Note: NO_SSLv3 / NO_TLSv1 don't trip the harness's forbidden-primitive
// scan because the regexes (\bSSLv3\b / \bDES-CBC\b) require a word
// boundary that a leading underscore satisfies asymmetrically — i.e.
// `_SSLv3` has a word-char `_` before `S`, so `\b` does NOT match there.
import { runStandardHelperSuite } from './_helpers/harness.js';
import squid from '../src/js/helpers/squid.js';

runStandardHelperSuite({
  name: 'squid',
  helper: squid,
  serverVersion: '6.12',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TLSv1_2,NO_TICKET\b/,
    intermediate: /options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET\b/,
    old:          /options=NO_SSLv3,NO_TICKET\b/,
  },
});
