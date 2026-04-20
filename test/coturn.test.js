// coturn helper — generic-suite tests via the shared harness.
//
// coturn (a TURN/STUN server) selects protocols by NEGATION:
// `no-sslv2`, `no-sslv3`, `no-tlsv1`, `no-tlsv1_1`, `no-tlsv1_2`.
// Token PRESENCE means the version is EXCLUDED, so we drive the harness
// in `negationVersionTokens` mode.
import { runStandardHelperSuite } from './_helpers/harness.js';
import coturn from '../src/js/helpers/coturn.js';

runStandardHelperSuite({
  name: 'coturn',
  helper: coturn,
  serverVersion: '4.6.2',
  supportsHsts: false,
  supportsCurveSelection: false,  // configs.js: coturn (TURN/STUN) cannot select TLS curves
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /no-sslv2\nno-sslv3\n/,
    intermediate: /no-sslv2\nno-sslv3\nno-tlsv1\nno-tlsv1_1\n/,
    modern:       /no-sslv2\nno-sslv3\nno-tlsv1\nno-tlsv1_1\nno-tlsv1_2\n/,
  },
  negationVersionTokens: {
    'TLSv1':   /^no-tlsv1$/m,
    'TLSv1.1': /^no-tlsv1_1$/m,
    'TLSv1.2': /^no-tlsv1_2$/m,
  },
});
