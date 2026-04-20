// postfix helper — generic-suite tests via the shared harness.
//
// Postfix 3.6+ uses a ">=TLSv1.x" minimum-floor syntax for both
// smtpd_tls_*_protocols and smtp_tls_*_protocols. Older versions emit a
// negation list (!SSLv2, !SSLv3, …) which we don't exercise here (we test
// the latest stable release). Postfix has no notion of HSTS.
import { runStandardHelperSuite } from './_helpers/harness.js';
import postfix from '../src/js/helpers/postfix.js';

runStandardHelperSuite({
  name: 'postfix',
  helper: postfix,
  serverVersion: '3.9.0',
  supportsHsts: false,
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /smtpd_tls_mandatory_protocols = >=TLSv1\.3\b/,
    intermediate: /smtpd_tls_mandatory_protocols = >=TLSv1\.2\b/,
    old:          /smtpd_tls_mandatory_protocols = >=TLSv1\b/,
  },
  // Postfix 3.6+ names only the floor protocol; per-version gating doesn't
  // apply. The harness will fall back to re-asserting protocolDirective.modern.
});
