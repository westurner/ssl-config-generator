// awselb helper — generic-suite tests via the shared harness.
//
// AWS (Classic) ELB exposes individual ciphers and protocols as named
// policy attributes: `- Name: Protocol-TLSv1.2 / Value: true` and
// `- Name: ECDHE-… / Value: true`. configs.js does not set cipherFormat
// → defaults to 'openssl', and ELB's supportedCiphers list IS in OpenSSL
// form. ELB has no HSTS support (configs.js: supportsHsts:false).
import { runStandardHelperSuite } from './_helpers/harness.js';
import awselb from '../src/js/helpers/awselb.js';

runStandardHelperSuite({
  name: 'awselb',
  helper: awselb,
  serverVersion: '2014.2.19',
  supportsHsts: false,
  supportsCurveSelection: false,    // configs.js: AWS ELB doesn't expose curve preference
  cipherFormat: 'openssl',
  protocolDirective: {
    modern:       /Name: Protocol-TLSv1\.3\b/,
    intermediate: /Name: Protocol-TLSv1\.2\b[\s\S]*Name: Protocol-TLSv1\.3\b/,
    old:          /Name: Protocol-TLSv1\b[\s\S]*Name: Protocol-TLSv1\.3\b/,
  },
  versionTokens: {
    'TLSv1.3': /Protocol-TLSv1\.3\b/,
    'TLSv1.2': /Protocol-TLSv1\.2\b/,
    'TLSv1.1': /Protocol-TLSv1\.1\b/,
    'TLSv1':   /Protocol-TLSv1(?![.\d])/,
  },
});
