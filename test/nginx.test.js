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
});
