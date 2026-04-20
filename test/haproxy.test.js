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
    modern:       /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.3\b/,
    intermediate: /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.2\b/,
    old:          /ssl-default-bind-options[^\n]*ssl-min-ver TLSv1\.0\b/,
  },
  // For protocol-gating: ssl-min-ver only ever names ONE version (the
  // lowest). So we don't supply versionTokens; the harness falls back to
  // re-asserting protocolDirective.modern when 1.3 is the only protocol.
  hstsHeader: /Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
});
