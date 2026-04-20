// apache (mod_ssl) helper — generic-suite tests via the shared harness.
import { runStandardHelperSuite } from './_helpers/harness.js';
import apache from '../src/js/helpers/apache.js';

runStandardHelperSuite({
  name: 'apache',
  helper: apache,
  serverVersion: '2.4.60',
  supportsHsts: true,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /SSLProtocol\s+-all \+TLSv1\.3\n/,
    intermediate: /SSLProtocol\s+-all \+TLSv1\.2 \+TLSv1\.3\n/,
    old:          /SSLProtocol\s+-all \+TLSv1 \+TLSv1\.1 \+TLSv1\.2 \+TLSv1\.3\n/,
  },
  versionTokens: {
    'TLSv1.3': /\+TLSv1\.3\b/,
    'TLSv1.2': /\+TLSv1\.2\b/,
    'TLSv1.1': /\+TLSv1\.1\b/,
    'TLSv1':   /\+TLSv1(?![.\d])/,
  },
  hstsHeader: /Header[^\n]*set Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
});
