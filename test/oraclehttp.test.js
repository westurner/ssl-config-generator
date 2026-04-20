// oraclehttp helper — generic-suite tests via the shared harness.
//
// Oracle HTTP uses Apache-derived `SSLProtocol -all +TLSv1.2 +TLSv1.3`
// syntax. configs.js declares cipherFormat:'iana'. HSTS is supported via
// `Header always set Strict-Transport-Security`.
import { runStandardHelperSuite } from './_helpers/harness.js';
import oraclehttp from '../src/js/helpers/oraclehttp.js';

runStandardHelperSuite({
  name: 'oraclehttp',
  helper: oraclehttp,
  serverVersion: '12.2.1',
  supportsHsts: true,
  supportsCurveSelection: false,  // configs.js: Oracle HTTP template doesn't render curves
  cipherFormat: 'iana',
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
  hstsHeader: /Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"/,
});
