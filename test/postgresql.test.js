// postgresql helper — generic-suite tests via the shared harness.
//
// PostgreSQL 12+ uses ssl_min_protocol_version. PostgreSQL has no notion
// of HSTS.
import runStandardHelperSuite from './_helpers/harness.js';
import postgresql from '../src/js/helpers/postgresql.js';

runStandardHelperSuite({
  name: 'postgresql',
  helper: postgresql,
  serverVersion: '17.2',
  supportsHsts: false,
  // PostgreSQL gained ssl_groups in v18; the latest stable shipped here is
  // 17.2, so the rendered config has no group line. Once configs.js bumps
  // the latest to 18+, drop this opt-out.
  supportsCurveSelection: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    old:          /ssl_min_protocol_version = 'TLSv1'/,
    intermediate: /ssl_min_protocol_version = 'TLSv1\.2'/,
    modern:       /ssl_min_protocol_version = 'TLSv1\.3'/,
  },
  // Sorted by serverVersion ascending; pre-10 omits ssl_dh_params_file;
  // pre-12 omits ssl_min_protocol_version; v18+ adds ssl_groups (configs.js
  // still ships v17, but we exercise the future branch for coverage).
  legacyVersions: [
    { serverVersion: '9.6',  label: 'pre-10 (no ssl_dh_params_file)' },
    { serverVersion: '11.0', label: 'pre-12 (no ssl_min_protocol_version)' },
    { serverVersion: '18.0', label: 'v18+ (ssl_groups branch)' },
  ],
});
