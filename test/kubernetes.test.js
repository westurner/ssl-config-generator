// kubernetes helper — generic-suite tests via the shared harness.
//
// configs.js declares cipherFormat:'go' for kubernetes (kube-apiserver and
// kubelet are Go binaries that consume IANA cipher names). state.js
// translates that to the IANA list in output.ciphers, so the harness
// option below is 'iana' — same convention as test/traefik.test.js and
// test/caddy.test.js.
//
// Curves: Kubernetes does not expose any per-curve / per-group knob, so
// supportsCurveSelection:false in configs.js. The harness's "curves
// emitted" category is opt-out via the makeOutput override below
// (supportsCurveSelection: false), and the helper is asked to surface
// the gap in its rendered comment block — the extraTests assertion
// below pins that requirement.
//
// HSTS: kube-apiserver gained --strict-transport-security-directives in
// v1.28; the helper emits the flag (as a comment) on 1.28+ clusters and
// a "front with a reverse proxy" note on older ones. The harness HSTS
// pattern below matches the apiserver flag spelling.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runStandardHelperSuite } from './_helpers/harness.js';
import { makeForm, makeOutput } from './_helpers/fixtures.js';
import kubernetes from '../src/js/helpers/kubernetes.js';

runStandardHelperSuite({
  name: 'kubernetes',
  helper: kubernetes,
  serverVersion: '1.34.0',
  supportsHsts: true,
  supportsCurveSelection: false,  // configs.js: K8s has no per-curve / tlsCurvePreferences knob
  cipherFormat: 'iana',
  supportsPq: true,
  protocolDirective: {
    // 'old' profile starts at TLSv1; helper maps that to "VersionTLS10"
    // (Go's crypto/tls constant naming). 'intermediate' starts at TLSv1.2,
    // 'modern' at TLSv1.3. Both KubeletConfiguration.tlsMinVersion and
    // kube-apiserver --tls-min-version use the same VersionTLS1N spelling.
    old:          /tlsMinVersion: VersionTLS10/,
    intermediate: /tlsMinVersion: VersionTLS12/,
    modern:       /tlsMinVersion: VersionTLS13/,
  },
  // The apiserver flag is emitted as a YAML comment line. Match
  // both the max-age=N value and the includeSubDomains directive,
  // matching the harness's default HSTS-includeSubDomains contract.
  hstsHeader: /--strict-transport-security-directives=max-age=63072000,includeSubDomains/,
  extraTests: (t) => {
    t('emits KubeletConfiguration apiVersion / kind preamble', () => {
      const out = kubernetes(
        makeForm({ serverVersion: '1.34.0', config: 'modern' }),
        makeOutput('modern', { cipherFormat: 'iana', supportsCurveSelection: false }),
      );
      assert.match(out, /apiVersion: kubelet\.config\.k8s\.io\/v1beta1/);
      assert.match(out, /kind: KubeletConfiguration/);
    });

    t('emits cert / key paths for both kubelet and apiserver', () => {
      const out = kubernetes(
        makeForm({ serverVersion: '1.34.0', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana', supportsCurveSelection: false }),
      );
      // kubelet KubeletConfiguration field
      assert.match(out, /^tlsCertFile: \/path\/to\/signed_cert_plus_intermediates$/m);
      assert.match(out, /^tlsPrivateKeyFile: \/path\/to\/private_key$/m);
      // kube-apiserver flag (commented)
      assert.match(out, /^#\s+--tls-cert-file=\/path\/to\/signed_cert_plus_intermediates$/m);
      assert.match(out, /^#\s+--tls-private-key-file=\/path\/to\/private_key$/m);
    });

    t('TLS 1.3-only profile omits tlsCipherSuites (Go does not expose TLS 1.3 cipher selection)', () => {
      // For the modern profile state.js puts an empty list in
      // output.ciphers (Go's crypto/tls treats CipherSuites as TLS 1.2-
      // only). The helper must therefore omit the tlsCipherSuites: key
      // entirely — emitting `tlsCipherSuites:` with no list items below
      // would be a YAML parse error.
      const out = kubernetes(
        makeForm({ serverVersion: '1.34.0', config: 'modern' }),
        makeOutput('modern', { cipherFormat: 'iana', supportsCurveSelection: false }),
      );
      assert.doesNotMatch(out, /tlsCipherSuites:/);
      assert.doesNotMatch(out, /--tls-cipher-suites=/);
    });

    t('intermediate profile emits IANA TLS 1.2 cipher list and matching --tls-cipher-suites flag', () => {
      const out = kubernetes(
        makeForm({ serverVersion: '1.34.0', config: 'intermediate' }),
        makeOutput('intermediate', { cipherFormat: 'iana', supportsCurveSelection: false }),
      );
      // YAML list under KubeletConfiguration
      assert.match(out, /tlsCipherSuites:\n- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/);
      // Comma-separated apiserver flag spelling
      assert.match(out, /--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,/);
    });

    t('PQ-only mode pins tlsMinVersion=VersionTLS13 and warns that group selection is not configurable', () => {
      const out = kubernetes(
        makeForm({ serverVersion: '1.34.0', config: 'modern', pq: 'only' }),
        makeOutput('modern', { cipherFormat: 'iana', supportsCurveSelection: false, supportsPq: true, pqMode: 'only' }),
      );
      assert.match(out, /tlsMinVersion: VersionTLS13/);
      assert.match(out, /PQ-only mode \(refuse classical-only key exchange\) cannot/);
      assert.match(out, /Config\.CurvePreferences as a configuration field/);
    });

    t('hybrid mode on a pre-1.34 cluster emits a Go-version WARNING', () => {
      // Kubernetes 1.33 was built with Go 1.23 (no X25519MLKEM768 in
      // crypto/tls's default group list). The helper must warn the
      // operator that PQ won't be negotiated until they upgrade.
      const out = kubernetes(
        makeForm({ serverVersion: '1.33.0', config: 'intermediate', pq: 'hybrid' }),
        makeOutput('intermediate', { cipherFormat: 'iana', supportsCurveSelection: false, supportsPq: true, pqMode: 'hybrid' }),
      );
      assert.match(out, /WARNING: Kubernetes 1\.33\.0 was built with a Go/);
      assert.match(out, /Upgrade to\s+#\s+Kubernetes 1\.34/);
    });

    t('HSTS on a pre-1.28 cluster emits the reverse-proxy fallback note (no apiserver flag)', () => {
      const out = kubernetes(
        makeForm({ serverVersion: '1.27.0', config: 'intermediate', hsts: true }),
        makeOutput('intermediate', { cipherFormat: 'iana', supportsCurveSelection: false }),
      );
      assert.doesNotMatch(out, /--strict-transport-security-directives=/);
      assert.match(out, /requires\n# kube-apiserver v1\.28\.0 or newer/);
      assert.match(out, /Front kube-apiserver with an HSTS-aware reverse proxy/);
    });
  },
});
