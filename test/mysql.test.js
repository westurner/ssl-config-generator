// mysql helper — generic-suite tests via the shared harness.
//
// MySQL lists every enabled version explicitly: tls_version = TLSv1.2,TLSv1.3
// — so per-version gating applies cleanly. No HSTS.
import { runStandardHelperSuite, BARE_TLSV1 } from './_helpers/harness.js';
import mysql from '../src/js/helpers/mysql.js';

runStandardHelperSuite({
  name: 'mysql',
  helper: mysql,
  serverVersion: '9.1.0',
  supportsHsts: false,
  supportsCurveSelection: false,  // configs.js: MySQL has no curve-preference directive
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /tls_version = TLSv1\.3\n/,
    intermediate: /tls_version = TLSv1\.2,TLSv1\.3\n/,
    old:          /tls_version = TLSv1,TLSv1\.1,TLSv1\.2,TLSv1\.3\n/,
  },
  versionTokens: {
    'TLSv1.3': /\bTLSv1\.3\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    'TLSv1':   BARE_TLSV1,
  },
});
