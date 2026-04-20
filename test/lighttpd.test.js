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
    old:          /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1"\)/m,
    intermediate: /^ssl\.openssl\.ssl-conf-cmd = \("MinProtocol" => "TLSv1\.2"\)/m,
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
  },
  // Only the floor is named; rely on protocolDirective fallback for gating.
  hstsHeader: /"Strict-Transport-Security" => "max-age=63072000; includeSubDomains"/,
  // Exercise older lighttpd / openssl combinations to hit the alternate
  // code paths (lighttpd 1.4.46 fork; openssl <1.1.0 / <1.0.2 forks).
  legacyVersions: [
    // Pre-1.4.46 (no `#server.modules += ("mod_openssl")` line).
    { serverVersion: '1.4.45', opensslVersion: '1.0.2', label: 'pre-1.4.46' },
    // Pre-1.4.48 in the legacy fork: hits the ssl.use-sslv2 else branch.
    { serverVersion: '1.4.47', opensslVersion: '1.0.2', label: 'pre-1.4.48 (use-sslv2/3 disable in legacy fork)' },
    // Pre-1.4.50 fork ($SERVER["socket"] == ":443" block). Each opensslVersion
    // hits a different ssl.openssl.ssl-conf-cmd / ssl.use-sslv2 path.
    { serverVersion: '1.4.49', opensslVersion: '1.0.0', label: 'pre-1.4.50 + OpenSSL 1.0.0 (use-sslv2/3 disable)' },
    { serverVersion: '1.4.49', opensslVersion: '1.0.2', label: 'pre-1.4.50 + OpenSSL 1.0.2 (Protocol=-ALL form)' },
    { serverVersion: '1.4.49', opensslVersion: '1.1.1', label: 'pre-1.4.50 + OpenSSL 1.1.0+' },
    // Pre-1.4.53 in the legacy fork: hits the alt cert/key path.
    { serverVersion: '1.4.52', opensslVersion: '1.0.2', label: 'pre-1.4.53 (legacy combined pemfile)' },
    // 1.4.50+ but openssl <1.1.0 (Protocol="-ALL,…" form, no MinProtocol).
    { serverVersion: '1.4.55', opensslVersion: '1.0.2', label: '1.4.50+ + OpenSSL 1.0.2' },
    // 1.4.50–1.4.66 (no comment-out logic for default protocol).
    { serverVersion: '1.4.55', opensslVersion: '1.1.0', label: '1.4.55 + OpenSSL 1.1.0' },
    // Pre-1.4.56 HSTS path (mod_redirect/mod_setenv commented out).
    { serverVersion: '1.4.55', opensslVersion: '1.1.1', label: 'pre-1.4.56 HSTS path' },
    // 1.4.67 (cipher-list always emitted, not commented; pre-1.4.68).
    { serverVersion: '1.4.67', opensslVersion: '1.1.1', label: '1.4.67 (pre-1.4.68 cipher path)' },
  ],
});
