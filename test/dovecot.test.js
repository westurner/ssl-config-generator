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
    old:          /ssl_min_protocol = TLSv1\b/,
    intermediate: /ssl_min_protocol = TLSv1\.2\b/,
    modern:       /ssl_min_protocol = TLSv1\.3\b/,
  },
  // Exercise pre-2.3 (ssl_protocols list, ssl_dh_parameters_length) and
  // pre-2.4 (ssl_cert/ssl_key/ssl_prefer_server_ciphers) code paths.
  legacyVersions: [
    { serverVersion: '2.2.36', label: 'pre-2.3 (legacy ssl_protocols + dh_parameters_length)' },
    { serverVersion: '2.3.21', label: '2.3.x (pre-2.4 cert directives)' },
  ],
});
