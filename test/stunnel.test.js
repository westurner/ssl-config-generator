// stunnel helper — generic-suite tests via the shared harness.
//
// stunnel 5.50+ uses sslVersionMin = TLSv1.x to set a minimum-version floor.
// stunnel proxies arbitrary TCP traffic; no HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import stunnel from '../src/js/helpers/stunnel.js';

runStandardHelperSuite({
  name: 'stunnel',
  helper: stunnel,
  serverVersion: '5.73',
  supportsHsts: false,
  cipherFormat: 'openssl',
  formOverrides: { opensslVersion: '3.0.0' },
  protocolDirective: {
    modern:       /sslVersionMin = TLSv1\.3\n/,
    intermediate: /sslVersionMin = TLSv1\.2\n/,
    old:          /sslVersionMin = TLSv1\n/,
  },
  // Pre-5.50 stunnel emits options = NO_TLSv1.x rather than sslVersionMin
  // (lines 17-21). Pre-1.0.1 OpenSSL adds NO_SSLv2/3 options (lines 23-27).
  // Pre-1.1.1 OpenSSL omits the curves= line (lines 29-32) and pre-1.0.2
  // omits checkHost= (line 47).
  legacyVersions: [
    { serverVersion: '5.40', opensslVersion: '1.0.0', label: 'pre-5.50 + pre-1.0.1 OpenSSL' },
    { serverVersion: '5.40', opensslVersion: '1.0.2', label: 'pre-5.50 + 1.0.2 OpenSSL' },
    { serverVersion: '5.73', opensslVersion: '1.1.0', label: 'modern stunnel + pre-1.1.1 OpenSSL (no curves)' },
  ],
});
