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
});
