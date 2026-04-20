// apache (mod_ssl) helper — generic-suite tests via the shared harness.
import runStandardHelperSuite from './_helpers/harness.js';
import apache from '../src/js/helpers/apache.js';

runStandardHelperSuite({
  name: 'apache',
  helper: apache,
  serverVersion: '2.4.60',
  supportsHsts: true,
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /SSLProtocol\s+-all \+TLSv1 \+TLSv1\.1 \+TLSv1\.2 \+TLSv1\.3\n/,
    intermediate: /SSLProtocol\s+-all \+TLSv1\.2 \+TLSv1\.3\n/,
    modern:       /SSLProtocol\s+-all \+TLSv1\.3\n/,
  },
  versionTokens: {
    'TLSv1':   /\+\bTLSv1\b(?![.\d])/,
    'TLSv1.1': /\+TLSv1\.1\b/,
    'TLSv1.2': /\+TLSv1\.2\b/,
    'TLSv1.3': /\+TLSv1\.3\b/,
  },
  hstsHeader: /Header[^\n]*set Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
  // Pre-2.4.17 omits the HTTP/2 Protocols line (lines 49-54); pre-2.4.7
  // emits the legacy SSLCertificateChainFile form (lines 40-44); pre-2.0.0
  // omits ` always` on the HSTS Header (line 60).
  legacyVersions: [
    { serverVersion: '2.4.10', label: 'pre-2.4.17 (no HTTP/2 Protocols line)' },
    { serverVersion: '2.4.6',  label: 'pre-2.4.7 (legacy SSLCertificateChainFile)' },
    { serverVersion: '1.3.42', label: 'pre-2.0 (no `always` on HSTS Header)' },
  ],
});
