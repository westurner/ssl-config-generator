// openlitespeed helper — generic-suite tests via the shared harness.
//
// OpenLiteSpeed shares LiteSpeed's numeric bitmask encoding for
// enabled protocols (16 = TLS1.3, 24 = TLS1.2+1.3, 30 = TLS1.0+).
// Cipher names and HSTS are emitted normally; OpenLiteSpeed's HSTS uses
// the same `Header Set Strict-Transport-Security` extraHeaders syntax.
import { runStandardHelperSuite } from './_helpers/harness.js';
import openlitespeed from '../src/js/helpers/openlitespeed.js';

runStandardHelperSuite({
  name: 'openlitespeed',
  helper: openlitespeed,
  serverVersion: '1.8.5',
  supportsHsts: true,
  supportsCurveSelection: false,  // configs.js: OpenLiteSpeed has no curve-preference directive
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /sslProtocol\s+16\b/,
    intermediate: /sslProtocol\s+24\b/,
    old:          /sslProtocol\s+30\b/,
  },
  hstsHeader: /Header Set Strict-Transport-Security: max-age=63072000; includeSubDomains/,
});
