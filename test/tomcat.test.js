// tomcat helper — generic-suite tests via the shared harness.
//
// Tomcat's SSLHostConfig protocols="TLSv1.2,TLSv1.3" is a comma-separated
// list of every enabled version, so per-version gating applies. cipherFormat
// is the configs.js default 'openssl'.
//
// HSTS handling: when form.hsts is true the helper emits an HTTP→HTTPS
// redirect Connector AND an actual <filter>/<filter-mapping> XML block
// referencing `org.apache.catalina.filters.HttpHeaderSecurityFilter`
// (Tomcat 8.5+). The version requirement is documented in a leading
// XML comment, but the filter elements themselves are emitted as live
// configuration so an operator can paste them straight into
// WEB-INF/web.xml. The harness's `Strict-Transport-Security […]
// includeSubDomains` assertion is satisfied by the rendered "Equivalent
// rendered response header:" example inside the comment block.
//
// supportsCurveSelection:false — Tomcat's SSLHostConfig doesn't expose a
// per-curve preference directive, so the harness skips the curves-presence
// check.
import runStandardHelperSuite from './_helpers/harness.js';
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
    old:          /protocols="TLSv1,TLSv1\.1,TLSv1\.2,TLSv1\.3"/,
    intermediate: /protocols="TLSv1\.2,TLSv1\.3"/,
    modern:       /protocols="TLSv1\.3"/,
  },
  versionTokens: {
    'TLSv1':   /\bTLSv1\b(?![.\d])/,
    'TLSv1.1': /\bTLSv1\.1\b/,
    'TLSv1.2': /\bTLSv1\.2\b/,
    'TLSv1.3': /\bTLSv1\.3\b/,
  },
  // The HSTS contract is encoded BOTH as an "Equivalent rendered response
  // header:" line in the leading comment AND as live <init-param> elements
  // (hstsEnabled / hstsMaxAgeSeconds / hstsIncludeSubDomains). The regex
  // here pins both: the rendered header form (which the harness's
  // case-insensitive includeSubDomains check consumes) AND the
  // <filter-class>HttpHeaderSecurityFilter, so a future regression that
  // accidentally re-comments the XML block will trip this test.
  hstsHeader: /Strict-Transport-Security:\s*max-age=63072000;\s*includeSubDomains[\s\S]*<filter-class>org\.apache\.catalina\.filters\.HttpHeaderSecurityFilter<\/filter-class>/,
});
