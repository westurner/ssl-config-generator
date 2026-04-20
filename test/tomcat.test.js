// tomcat helper — generic-suite tests via the shared harness.
//
// Tomcat's SSLHostConfig protocols="TLSv1.2,TLSv1.3" is a comma-separated
// list of every enabled version, so per-version gating applies. cipherFormat
// is the configs.js default 'openssl'.
//
// HSTS handling: when form.hsts is true the helper emits an HTTP→HTTPS
// redirect Connector AND an XML-comment block containing a ready-to-paste
// `org.apache.catalina.filters.HttpHeaderSecurityFilter` <filter> snippet
// for WEB-INF/web.xml (Tomcat 8.5+). The harness's `Strict-Transport-Security
// […] includeSubDomains` assertion is satisfied by the rendered "Equivalent
// rendered response header:" example inside the comment block.
//
// supportsCurveSelection:false — Tomcat's SSLHostConfig doesn't expose a
// per-curve preference directive, so the harness skips the curves-presence
// check.
import { runStandardHelperSuite, BARE_TLSV1 } from './_helpers/harness.js';
import tomcat from '../src/js/helpers/tomcat.js';

runStandardHelperSuite({
  name: 'tomcat',
  helper: tomcat,
  serverVersion: '11.0.1',
  supportsHsts: true,
  supportsCurveSelection: false,
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
    'TLSv1':   BARE_TLSV1,
  },
  // The HSTS contract for the web.xml HttpHeaderSecurityFilter is encoded as
  // an "Equivalent rendered response header:" line inside the XML comment
  // block — assert on that line so the test mirrors what an operator sees
  // and what their HTTP responses will actually contain.
  hstsHeader: /Strict-Transport-Security:\s*max-age=63072000;\s*includeSubDomains/,
});
