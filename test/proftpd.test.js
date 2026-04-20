// proftpd helper — generic-suite tests via the shared harness.
//
// ProFTPD's TLSProtocol directive lists each enabled version
// (TLSProtocol TLSv1.2 TLSv1.3). It's an FTP server with no HSTS notion.
import { runStandardHelperSuite } from './_helpers/harness.js';
import proftpd from '../src/js/helpers/proftpd.js';

runStandardHelperSuite({
  name: 'proftpd',
  helper: proftpd,
  serverVersion: '1.3.8',
  supportsHsts: false,
  cipherFormat: 'openssl',
  formOverrides: { opensslVersion: '3.0.0' },
  protocolDirective: {
    modern:       /TLSProtocol\s+TLSv1\.3\n/,
    intermediate: /TLSProtocol\s+TLSv1\.2 TLSv1\.3\n/,
    old:          /TLSProtocol\s+TLSv1 TLSv1\.1 TLSv1\.2 TLSv1\.3\n/,
  },
  versionTokens: {
    'TLSv1.3': /\bTLSv1\.3\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    'TLSv1':   /\bTLSv1(?![.\d])/,
  },
});
