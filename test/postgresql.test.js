// postgresql helper — generic-suite tests via the shared harness.
//
// PostgreSQL 12+ uses ssl_min_protocol_version. PostgreSQL has no notion
// of HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import postgresql from '../src/js/helpers/postgresql.js';

runStandardHelperSuite({
  name: 'postgresql',
  helper: postgresql,
  serverVersion: '17.2',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /ssl_min_protocol_version = 'TLSv1\.3'/,
    intermediate: /ssl_min_protocol_version = 'TLSv1\.2'/,
    old:          /ssl_min_protocol_version = 'TLSv1'/,
  },
});
