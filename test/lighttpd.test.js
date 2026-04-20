// lighttpd helper — generic-suite tests via the shared harness.
//
// lighttpd 1.4.50+ with OpenSSL 1.1+ uses a single ssl-conf-cmd MinProtocol
// directive. From 1.4.77 onwards, the line is COMMENTED OUT when its value
// matches the lighttpd default (TLSv1.3) — protocolDirective.modern must
// account for the leading '#'. lighttpd is a webserver; HSTS is supported.
import { runStandardHelperSuite } from './_helpers/harness.js';
import lighttpd from '../src/js/helpers/lighttpd.js';

runStandardHelperSuite({
  name: 'lighttpd',
  helper: lighttpd,
  serverVersion: '1.4.82',
  supportsHsts: true,
  cipherFormat: 'openssl',
  formOverrides: { opensslVersion: '3.0.0' },
  protocolDirective: {
    // 1.4.82 ≥ 1.4.77 + protocols[0]==='TLSv1.3' → line is commented
    // (lighttpd default); regex tolerates the leading '#'.
    modern:       /^#?ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1\.3"\)/m,
    intermediate: /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1\.2"\)/m,
    old:          /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1"\)/m,
  },
  // Only the floor is named; rely on protocolDirective fallback for gating.
  hstsHeader: /"Strict-Transport-Security" => "max-age=63072000; includeSubDomains"/,
});
