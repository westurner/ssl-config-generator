// litespeed helper — generic-suite tests via the shared harness.
//
// LiteSpeed encodes the enabled-protocol set as a numeric bitmask
// (<sslProtocol>16</sslProtocol> = TLS1.3, 24 = TLS1.2+1.3, 30 = TLS1.0+).
// Because no TLS-version strings are emitted, we opt out of strict
// per-version gating (versionTokens) and rely on protocolDirective's
// per-profile mask numbers. Cipher names and HSTS are emitted normally.
import { runStandardHelperSuite } from './_helpers/harness.js';
import litespeed from '../src/js/helpers/litespeed.js';

runStandardHelperSuite({
  name: 'litespeed',
  helper: litespeed,
  serverVersion: '6.3.5',
  supportsHsts: true,
  supportsCurveSelection: false,  // configs.js: LiteSpeed has no curve-preference directive
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /<sslProtocol>30<\/sslProtocol>/,
    intermediate: /<sslProtocol>24<\/sslProtocol>/,
    modern:       /<sslProtocol>16<\/sslProtocol>/,
  },
  hstsHeader: /Header Set Strict-Transport-Security: max-age=63072000; includeSubDomains/,
});
