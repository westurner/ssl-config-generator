// nginx helper — generic-suite tests via the shared harness.
import { runStandardHelperSuite, BARE_TLSV1 } from './_helpers/harness.js';
import nginx from '../src/js/helpers/nginx.js';

runStandardHelperSuite({
  name: 'nginx',
  helper: nginx,
  serverVersion: '1.27.3',
  supportsHsts: true,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /ssl_protocols\s+TLSv1\.3;/,
    intermediate: /ssl_protocols\s+TLSv1\.2 TLSv1\.3;/,
    old:          /ssl_protocols\s+TLSv1 TLSv1\.1 TLSv1\.2 TLSv1\.3;/,
  },
  versionTokens: {
    'TLSv1.3': /\bTLSv1\.3\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    // bare TLSv1, not followed by a dotted-decimal extension
    'TLSv1':   BARE_TLSV1,
  },
  hstsHeader: /add_header Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
  // Pre-1.25.1 uses `listen 443 ssl http2;` (lines 18-21); pre-1.9.5 uses
  // `listen 443 ssl;` without http2 (lines 23-24); pre-1.7.5 omits ` always`
  // on Header (line 33); pre-1.23.2 + ≥1.5.9 + ≥1.0.2l hits the
  // ssl_session_tickets off branch (lines 65-70).
  legacyVersions: [
    { serverVersion: '1.9.0',  opensslVersion: '1.0.1', label: 'pre-1.9.5 + pre-1.0.2l (no http2, no session_tickets)' },
    { serverVersion: '1.20.0', opensslVersion: '1.0.2l', label: '1.20 + 1.0.2l (ssl_session_tickets off branch)' },
    { serverVersion: '1.7.0',  opensslVersion: '1.0.2', label: 'pre-1.7.5 (no `always` on Header)' },
  ],
});
