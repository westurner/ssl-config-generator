// haproxy helper — generic-suite tests via the shared harness.
//
// HAProxy expresses protocol selection as a single ssl-min-ver directive
// (since 2.2), not as a per-version list, so versionTokens here describes
// "this version is the minimum" rather than "this version was emitted".
import { runStandardHelperSuite } from './_helpers/harness.js';
import haproxy from '../src/js/helpers/haproxy.js';

runStandardHelperSuite({
  name: 'haproxy',
  helper: haproxy,
  serverVersion: '3.0',
  supportsHsts: true,
  cipherFormat: 'openssl',
  protocolDirective: {
    // HAProxy 2.2+ emits "ssl-min-ver" with the lowest version in the list.
    // The 'old' profile starts at TLSv1, which the helper renders as
    // "TLSv1.0".
    old:          /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.0\b/,
    intermediate: /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.2\b/,
    modern:       /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.3\b/,
  },
  // For protocol-gating: ssl-min-ver only ever names ONE version (the
  // lowest). So we don't supply versionTokens; the harness falls back to
  // re-asserting protocolDirective.modern when 1.3 is the only protocol.
  hstsHeader: /Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
  // Exercise older HAProxy releases. Pre-1.5 returns the "TLS not supported"
  // banner (line 6), which is intentional. The harness's legacy-smoke check
  // only asserts no forbidden primitives — that holds for the banner string.
  // Pre-1.6 uses tune.ssl.default-dh-param (line 61); pre-1.8 omits ALPN
  // (line 67); pre-1.9 omits ssl-default-…-ciphersuites (line 22); pre-2.2
  // emits the no-sslv3 / no-tlsvNN negation list (lines 29-32); 1.5/2.x with
  // OpenSSL 3 + DHE + TLSv1.1 hits the ssl-security-level 0 branch.
  legacyVersions: [
    { serverVersion: '1.4.27',                              label: 'pre-1.5 (TLS not supported banner)' },
    { serverVersion: '1.5.20', opensslVersion: '1.0.1',     label: '1.5.x + OpenSSL 1.0 (legacy dh-param + negation list)' },
    { serverVersion: '1.7.12', opensslVersion: '1.0.2',     label: '1.7.x (pre-1.8 ALPN; pre-1.9 ciphersuites)' },
    { serverVersion: '2.1.0',  opensslVersion: '1.1.1',     label: '2.1 (pre-2.2 negation list)' },
    { serverVersion: '3.0',    opensslVersion: '3.0.0',     label: '3.0 + OpenSSL 3 (ssl-security-level branch)' },
  ],
});
