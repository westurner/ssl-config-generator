// redis helper — generic-suite tests via the shared harness.
//
// Redis 6.0+ supports TLS via tls-protocols "TLSv1.2 TLSv1.3" (each
// version listed). Redis is a key-value store; no HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import redis from '../src/js/helpers/redis.js';

runStandardHelperSuite({
  name: 'redis',
  helper: redis,
  serverVersion: '7.4.1',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /tls-protocols "TLSv1\.3"/,
    intermediate: /tls-protocols "TLSv1\.2 TLSv1\.3"/,
    old:          /tls-protocols "TLSv1 TLSv1\.1 TLSv1\.2 TLSv1\.3"/,
  },
  versionTokens: {
    'TLSv1.3': /\bTLSv1\.3\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    'TLSv1':   /\bTLSv1(?![.\d])/,
  },
});
