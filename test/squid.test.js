// squid helper — generic-suite tests via the shared harness.
//
// Squid selects protocols by NEGATION on the `options=` field:
// `options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET`. Token PRESENCE means
// the version is EXCLUDED, so we use the harness's `negationVersionTokens`
// mode. The harness's pre-pass strips `NO_…` tokens before scanning for
// forbidden primitives, so `NO_SSLv3` no longer trips the SSLv3 forbidden
// regex (it's the OPPOSITE of an SSLv3 mention — it disables SSLv3).
import runStandardHelperSuite from './_helpers/harness.js';
import squid from '../src/js/helpers/squid.js';

runStandardHelperSuite({
  name: 'squid',
  helper: squid,
  serverVersion: '6.12',
  supportsHsts: false,
  supportsCurveSelection: false,  // configs.js: Squid has no curve-preference directive
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /options=NO_SSLv3,NO_TICKET\b/,
    intermediate: /options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET\b/,
    modern:       /options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TLSv1_2,NO_TICKET\b/,
  },
  negationVersionTokens: {
    'TLSv1':   /\bNO_TLSv1\b(?!_)/,
    'TLSv1.1': /\bNO_TLSv1_1\b/,
    'TLSv1.2': /\bNO_TLSv1_2\b/,
  },
});
