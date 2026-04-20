// lighttpd helper — generic-suite tests via the shared harness.
//
// lighttpd 1.4.50+ with OpenSSL 1.1+ uses a single ssl-conf-cmd MinProtocol
// directive. From 1.4.77 onwards, the line is COMMENTED OUT when its value
// matches the lighttpd default (TLSv1.3) — protocolDirective.modern must
// account for the leading '#' AND for the trailing
// "# lighttpd <serverVersion> TLS default" annotation that lighttpd.js
// appends so the operator knows the commented line is intentional. lighttpd
// is a webserver; HSTS is supported.
import { runStandardHelperSuite } from './_helpers/harness.js';
import lighttpd from '../src/js/helpers/lighttpd.js';

const SERVER_VERSION = '1.4.82';

runStandardHelperSuite({
  name: 'lighttpd',
  helper: lighttpd,
  serverVersion: SERVER_VERSION,
  supportsHsts: true,
  cipherFormat: 'openssl',
  formOverrides: { opensslVersion: '3.0.0' },
  protocolDirective: {
    // 1.4.82 ≥ 1.4.77 + protocols[0]==='TLSv1.3' → line is commented out
    // (lighttpd default). The comment form MUST also carry the trailing
    // "lighttpd <ver> TLS default" annotation lighttpd.js renders from
    // form.serverVersion, so the operator knows the commented line is
    // intentional, not a bug. SERVER_VERSION above is escaped for the
    // regex literal — when bumping the version, update the constant only.
    modern:       new RegExp(
      '^#ssl\\.openssl\\.ssl-conf-cmd = \\("MinProtocol" => "TLSv1\\.3"\\)\\s+# lighttpd ' +
      SERVER_VERSION.replace(/\./g, '\\.') + ' TLS default',
      'm',
    ),
    intermediate: /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1\.2"\)/m,
    old:          /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1"\)/m,
  },
  // Only the floor is named; rely on protocolDirective fallback for gating.
  hstsHeader: /"Strict-Transport-Security" => "max-age=63072000; includeSubDomains"/,
});
