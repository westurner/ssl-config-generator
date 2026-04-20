// coturn helper — generic-suite tests via the shared harness.
//
// coturn (a TURN/STUN server) selects protocols by NEGATION:
// `no-sslv2`, `no-sslv3`, `no-tlsv1`, `no-tlsv1_1`, `no-tlsv1_2`.
// Per-version gating doesn't apply (a token's PRESENCE means the version
// is excluded), so we pin the negation block per profile via
// protocolDirective. No HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import coturn from '../src/js/helpers/coturn.js';

runStandardHelperSuite({
  name: 'coturn',
  helper: coturn,
  serverVersion: '4.6.2',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /no-sslv2\nno-sslv3\nno-tlsv1\nno-tlsv1_1\nno-tlsv1_2\n/,
    intermediate: /no-sslv2\nno-sslv3\nno-tlsv1\nno-tlsv1_1\n/,
    old:          /no-sslv2\nno-sslv3\n/,
  },
});
