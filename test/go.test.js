// go helper — generic-suite tests via the shared harness.
//
// Go's crypto/tls accepts a single MinVersion (no per-version list) and
// names protocols as tls.VersionTLS10/12/13. cipherFormat is 'go' →
// helper renders IANA-style names with a `tls.` prefix. Go uses //
// line-comments rather than #, so the harness's commentLine regex needs
// overriding for the protocol-gating step.
import runStandardHelperSuite from './_helpers/harness.js';
import go from '../src/js/helpers/go.js';

runStandardHelperSuite({
  name: 'go',
  helper: go,
  serverVersion: '1.23.3',
  supportsHsts: true,
  cipherFormat: 'go',
  supportsPq: true,  // Go 1.24+ exposes X25519MLKEM768 via tls.CurvePreferences.
  commentLine: /^\s*\/\/.*$/gm,
  protocolDirective: {
    // The 'old' Mozilla profile floor is TLSv1 (state.js spelling), which
    // go.js maps to VersionTLS10.
    old:          /MinVersion: tls\.VersionTLS10,/,
    intermediate: /MinVersion: tls\.VersionTLS12,/,
    modern:       /MinVersion: tls\.VersionTLS13,/,
  },
  // Go's tls.Config exposes only MinVersion; per-version gating isn't
  // meaningful, so we let the harness fall back to protocolDirective.modern.
  hstsHeader: /Strict-Transport-Security"[^\n]*max-age=63072000; includeSubDomains/,
});
