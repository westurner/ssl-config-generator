// exim helper — generic-suite tests via the shared harness.
//
// Exim selects protocols by NEGATION: openssl_options = +no_sslv2 +no_sslv3
// [+no_tlsv1 …]. The token's PRESENCE means the version is EXCLUDED, so
// we use the harness's `negationVersionTokens` mode: the harness asserts
// the token is present iff that version is NOT in output.protocols.
import runStandardHelperSuite from './_helpers/harness.js';
import exim from '../src/js/helpers/exim.js';

runStandardHelperSuite({
  name: 'exim',
  helper: exim,
  serverVersion: '4.98',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /openssl_options = \+no_sslv2 \+no_sslv3\n/,
    intermediate: /openssl_options = \+no_sslv2 \+no_sslv3 \+no_tlsv1 \+no_tlsv1_1\n/,
    modern:       /openssl_options = \+no_sslv2 \+no_sslv3 \+no_tlsv1 \+no_tlsv1_1 \+no_tlsv1_2\n/,
  },
  negationVersionTokens: {
    'TLSv1':   /\+no_tlsv1\b(?!_)/,
    'TLSv1.1': /\+no_tlsv1_1\b/,
    'TLSv1.2': /\+no_tlsv1_2\b/,
  },
});
