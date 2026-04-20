// awsalb helper — generic-suite tests via the shared harness.
//
// AWS Application Load Balancer doesn't allow per-cipher / per-protocol
// configuration; the helper picks one of three managed SSL policy names
// based on output.protocols. Likewise, ALB has no native HSTS — the helper
// emits an HTTP→HTTPS redirect rule when form.hsts is true. Both
// limitations are surfaced as user-visible warnings in the rendered
// CloudFormation, so we opt-out of cipherSyntax + hsts via the warning
// regex (no silent skips).
import { runStandardHelperSuite } from './_helpers/harness.js';
import awsalb from '../src/js/helpers/awsalb.js';

runStandardHelperSuite({
  name: 'awsalb',
  helper: awsalb,
  serverVersion: '2023.3.22',
  supportsHsts: true,        // matches configs.js default
  supportsCurveSelection: false,  // configs.js: AWS ALB exposes only managed policy names
  cipherFormat: 'openssl',   // not actually used (cipherSyntax is opted out)
  formOverrides: { serverName: 'AWS ALB' },
  protocolDirective: {
    // ALB picks a single managed-policy string per profile.
    old:          /SslPolicy: ELBSecurityPolicy-TLS-1-0-2015-04\b/,
    intermediate: /SslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-2021-06\b/,
    modern:       /SslPolicy: ELBSecurityPolicy-TLS13-1-3-2021-06\b/,
  },
  optOuts: {
    // The helper documents up-front that ALB doesn't expose ciphers/protocols
    // directly. That comment IS the warning we require.
    cipherSyntax: { warning: /don't allow you to directly specify protocols\s*\n#\s*and ciphers/ },
    // The helper's HSTS branch is an explicit "doesn't support HSTS, but
    // it can redirect to HTTPS" comment — exactly the user-visible
    // warning the opt-out contract requires.
    hsts:         { warning: /doesn't support HSTS, but it can redirect to HTTPS/ },
  },
});
