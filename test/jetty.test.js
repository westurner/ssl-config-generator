// jetty helper — generic-suite tests via the shared harness.
//
// Jetty's SslContextFactory takes an explicit IncludeProtocols array
// (`<Item>TLSv1.3</Item>` etc.), so per-version gating applies cleanly.
// Jetty's helper uses XML comments (`<!-- … -->`); the harness's default
// '#' commentLine regex must be overridden so the explanatory
// `<!-- TLSv1.3 requires Java 11 or higher -->` comment doesn't false-positive
// the protocol-gating check. Jetty has no built-in HSTS support.
import { runStandardHelperSuite } from './_helpers/harness.js';
import jetty from '../src/js/helpers/jetty.js';

runStandardHelperSuite({
  name: 'jetty',
  helper: jetty,
  serverVersion: '12.0.15',
  supportsHsts: false,
  supportsCurveSelection: false,  // configs.js: Jetty SslContextFactory has no curve API
  cipherFormat: 'iana',
  // Strip XML comments before the protocol-gating check.
  commentLine: /<!--[\s\S]*?-->/g,
  protocolDirective: {
    old:          /<Item>TLSv1<\/Item>[\s\S]*<Item>TLSv1\.3<\/Item>/,
    intermediate: /<Item>TLSv1\.2<\/Item>[\s\S]*<Item>TLSv1\.3<\/Item>/,
    modern:       /<Item>TLSv1\.3<\/Item>/,
  },
  versionTokens: {
    'TLSv1':   /<Item>TLSv1<\/Item>/,
    'TLSv1.1': /<Item>TLSv1\.1<\/Item>/,
    'TLSv1.2': /<Item>TLSv1\.2<\/Item>/,
    'TLSv1.3': /<Item>TLSv1\.3<\/Item>/,
  },
});
