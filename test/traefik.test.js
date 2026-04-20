// traefik helper — generic-suite tests via the shared harness.
//
// Traefik 2.x uses TOML keys minVersion = "VersionTLS12" / "VersionTLS13".
// configs.js declares cipherFormat:'go' for Traefik, which state.js (state.js:140)
// translates to the IANA cipher list in output.ciphers. The harness option
// below uses 'iana' because that matches the rendered form Traefik emits
// (bare IANA names, no `tls.` prefix); both 'go' and 'iana' produce the
// same output.ciphers for state.js's purposes.
import runStandardHelperSuite from './_helpers/harness.js';
import traefik from '../src/js/helpers/traefik.js';

runStandardHelperSuite({
  name: 'traefik',
  helper: traefik,
  serverVersion: '3.2.1',
  supportsHsts: true,
  cipherFormat: 'iana',  // Traefik renders bare IANA names inside cipherSuites=[…].
  supportsPq: true,      // Traefik 2.x exposes X25519MLKEM768 via curvePreferences.
  protocolDirective: {
    // 'old' profile starts at TLSv1; the helper maps that to "VersionTLS10".
    old:          /minVersion = "VersionTLS10"/,
    intermediate: /minVersion = "VersionTLS12"/,
    modern:       /minVersion = "VersionTLS13"/,
  },
  // Traefik names only the minimum version. Skip per-version gating (the
  // harness will re-check protocolDirective.modern instead).
  // Traefik 2.0+ supports stsIncludeSubdomains (Headers middleware).
  // The helper now emits it uncommented when form.hsts is enabled,
  // matching every other supportsHsts:true helper and the harness's
  // default HSTS-includeSubDomains contract.
  hstsHeader: /stsSeconds = 63072000\n\s+stsIncludeSubdomains = true/,
  // Exercise the legacy 1.x configuration path (different syntax) and
  // the PQ-only branch.
  legacyVersions: [
    { serverVersion: '1.7.34', label: 'traefik 1.x (defaultEntryPoints style)' },
  ],
  extraTests: (t) => {
    // Cover the PQ-only branch: helper emits an explanatory comment about
    // Traefik exposing only X25519MLKEM768 via curvePreferences.
    t('PQ-only mode emits the X25519MLKEM768 explanatory comment', async () => {
      const { default: traefikH } = await import('../src/js/helpers/traefik.js');
      const { makeForm, makeOutput } = await import('./_helpers/fixtures.js');
      const out = traefikH(
        makeForm({ serverVersion: '3.2.1', config: 'modern', pq: 'only', hsts: false }),
        makeOutput('modern', { cipherFormat: 'iana' }),
      );
      // The PQ-only comment is emitted inside [tls.options.modern]; assert
      // its presence so a future refactor that drops the explanation trips.
      const { default: assert } = await import('node:assert/strict');
      assert.match(out, /PQ-only: Traefik currently only exposes the X25519MLKEM768/);
    });
  },
});
