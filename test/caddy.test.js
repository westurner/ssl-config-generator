// caddy helper — generic-suite tests via the shared harness.
//
// Caddy consumes IANA-style cipher names (configs.js declares
// cipherFormat:'go', which state.js maps onto the IANA cipher list).
import { runStandardHelperSuite } from './_helpers/harness.js';
import caddy from '../src/js/helpers/caddy.js';

runStandardHelperSuite({
  name: 'caddy',
  helper: caddy,
  serverVersion: '2.8.4',
  supportsHsts: true,
  cipherFormat: 'iana',  // Caddy renders bare IANA names (TLS_…) without a prefix.
  protocolDirective: {
    // Caddy emits a `protocols tls1.3` line only when TLS1.2 is NOT in the
    // list; otherwise it leaves a commented-out `#protocols tls1.2 tls1.3`
    // (Caddy's safe defaults). Both 'intermediate' and 'old' include
    // TLSv1.2, so they take the commented form.
    modern:       /^\s*protocols tls1\.3\b/m,
    intermediate: /^\s*#protocols tls1\.2 tls1\.3\b/m,
    old:          /^\s*#protocols tls1\.2 tls1\.3\b/m,
  },
  versionTokens: {
    // Caddy supports only TLSv1.2+. The helper says so in a comment and
    // drops a `protocols` line only for the strict-1.3 case. Because the
    // older versions never appear as enable-tokens in the rendered config,
    // a strict per-version mapping isn't meaningful here.
    'TLSv1.3': /\btls1\.3\b/,
  },
  hstsHeader: /header Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
  // Pre-2.0 Caddy emits the v1 EOL banner (lines 8-12); the PQ-only branch
  // adds an explanatory comment (lines 41-45).
  legacyVersions: [
    { serverVersion: '1.0.5', label: 'pre-2.0 (v1 EOL banner)' },
  ],
  extraTests: (t) => {
    t('PQ-only mode emits the X25519MLKEM768 explanatory comment', async () => {
      const { default: caddyH } = await import('../src/js/helpers/caddy.js');
      const { makeForm, makeOutput } = await import('./_helpers/fixtures.js');
      const { default: assert } = await import('node:assert/strict');
      const out = caddyH(
        makeForm({ serverVersion: '2.8.4', config: 'modern', pq: 'only' }),
        makeOutput('modern', { cipherFormat: 'iana' }),
      );
      assert.match(out, /PQ-only: Caddy currently only exposes the X25519MLKEM768 hybrid/);
    });
  },
});
