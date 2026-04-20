// exim helper — generic-suite tests via the shared harness.
//
// Exim selects protocols by NEGATION: openssl_options = +no_sslv2 +no_sslv3
// [+no_tlsv1 …]. The set of negations is the inverse of output.protocols,
// so per-version gating doesn't directly apply (a token's PRESENCE means
// the version is excluded, not enabled). We instead pin the full openssl_options
// line per profile via protocolDirective. Exim is an SMTP server; no HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import exim from '../src/js/helpers/exim.js';

runStandardHelperSuite({
  name: 'exim',
  helper: exim,
  serverVersion: '4.98',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /openssl_options = \+no_sslv2 \+no_sslv3 \+no_tlsv1 \+no_tlsv1_1 \+no_tlsv1_2\n/,
    intermediate: /openssl_options = \+no_sslv2 \+no_sslv3 \+no_tlsv1 \+no_tlsv1_1\n/,
    old:          /openssl_options = \+no_sslv2 \+no_sslv3\n/,
  },
});
