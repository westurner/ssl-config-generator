// traefik helper — generic-suite tests via the shared harness.
//
// Traefik 2.x uses TOML keys minVersion = "VersionTLS12" / "VersionTLS13".
// configs.js declares cipherFormat:'go' for Traefik, which state.js (state.js:140)
// translates to the IANA cipher list in output.ciphers. The harness option
// below uses 'iana' because that matches the rendered form Traefik emits
// (bare IANA names, no `tls.` prefix); both 'go' and 'iana' produce the
// same output.ciphers for state.js's purposes.
import { runStandardHelperSuite } from './_helpers/harness.js';
import traefik from '../src/js/helpers/traefik.js';

runStandardHelperSuite({
  name: 'traefik',
  helper: traefik,
  serverVersion: '3.2.1',
  supportsHsts: true,
  cipherFormat: 'iana',  // Traefik renders bare IANA names inside cipherSuites=[…].
  protocolDirective: {
    modern:       /minVersion = "VersionTLS13"/,
    intermediate: /minVersion = "VersionTLS12"/,
    // 'old' profile starts at TLSv1; the helper maps that to "VersionTLS10".
    old:          /minVersion = "VersionTLS10"/,
  },
  // Traefik names only the minimum version. Skip per-version gating (the
  // harness will re-check protocolDirective.modern instead).
  hstsHeader: /stsSeconds = 63072000/,
});
