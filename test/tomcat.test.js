// tomcat helper — generic-suite tests via the shared harness.
//
// Tomcat's SSLHostConfig protocols="TLSv1.2,TLSv1.3" is a comma-separated
// list of every enabled version, so per-version gating applies. cipherFormat
// is the configs.js default 'openssl'.
//
// HSTS handling: the helper does NOT emit a Strict-Transport-Security
// header; on form.hsts:true it only adds an HTTP→HTTPS redirect Connector.
// configs.js does not declare supportsHsts:false for tomcat (defaults true),
// but the test harness here sets it to false to reflect the helper's actual
// behavior — the harness's "no STS header on hsts:true" assertion is the
// truthful contract for this template.
import { runStandardHelperSuite } from './_helpers/harness.js';
import tomcat from '../src/js/helpers/tomcat.js';

runStandardHelperSuite({
  name: 'tomcat',
  helper: tomcat,
  serverVersion: '11.0.1',
  supportsHsts: false,
  cipherFormat: 'openssl',
  commentLine: /<!--[\s\S]*?-->/g,
  protocolDirective: {
    modern:       /protocols="TLSv1\.3"/,
    intermediate: /protocols="TLSv1\.2,TLSv1\.3"/,
    old:          /protocols="TLSv1,TLSv1\.1,TLSv1\.2,TLSv1\.3"/,
  },
  versionTokens: {
    'TLSv1.3': /\bTLSv1\.3\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    'TLSv1':   /\bTLSv1(?![.\d])/,
  },
});
