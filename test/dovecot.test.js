// dovecot helper — generic-suite tests via the shared harness.
//
// Dovecot 2.3+ uses ssl_min_protocol = TLSv1.x to set a minimum-version
// floor (older releases listed each protocol explicitly). Dovecot is an
// IMAP/POP3 server with no notion of HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import dovecot from '../src/js/helpers/dovecot.js';

runStandardHelperSuite({
  name: 'dovecot',
  helper: dovecot,
  serverVersion: '2.4.2',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /ssl_min_protocol = TLSv1\.3\b/,
    intermediate: /ssl_min_protocol = TLSv1\.2\b/,
    old:          /ssl_min_protocol = TLSv1\b/,
  },
});
