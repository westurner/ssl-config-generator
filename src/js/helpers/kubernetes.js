// Kubernetes helper.
//
// Emits a KubeletConfiguration YAML snippet suitable for `kubelet --config`,
// plus equivalent `kube-apiserver` command-line flags as comments. Both
// surfaces accept the same values for the directives this helper renders:
//
//   * tlsMinVersion          / --tls-min-version
//   * tlsCipherSuites        / --tls-cipher-suites
//   * tlsCertFile            / --tls-cert-file
//   * tlsPrivateKeyFile      / --tls-private-key-file
//   * (kube-apiserver only)  --strict-transport-security-directives
//
// References:
//   - KubeletConfiguration v1beta1 reference (tlsMinVersion,
//     tlsCipherSuites, tlsCertFile, tlsPrivateKeyFile):
//     https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
//   - kube-apiserver command-line reference (--tls-min-version,
//     --tls-cipher-suites, --strict-transport-security-directives):
//     https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
//   - "Post-Quantum Cryptography in Kubernetes" (Kubernetes blog,
//     2025-07-18): https://kubernetes.io/blog/2025/07/18/pqc-in-k8s/
//
// Cipher / curve / PQ surface
// ---------------------------
// Kubernetes components (kube-apiserver, kubelet, kube-controller-manager,
// kube-scheduler, kube-proxy) are Go binaries built against crypto/tls.
// crypto/tls accepts only IANA cipher names (TLS_…) — not OpenSSL names —
// so this helper consumes output.ciphers in the IANA spelling. configs.js
// declares cipherFormat:'go' for kubernetes; state.js (state.js:140)
// translates that to the IANA list in output.ciphers (the same path Go
// itself, Caddy, and Traefik use).
//
// Kubernetes does NOT expose a curve / group preference knob — neither
// `--tls-curve-preferences` nor a tlsCurvePreferences field on
// KubeletConfiguration. The underlying Go field is
// `crypto/tls.Config.CurvePreferences []CurveID`, which determines the
// order TLS named groups (a.k.a. "curves") are offered and selected for
// ECDHE / hybrid key exchange — see https://pkg.go.dev/crypto/tls#Config
// and the "Go" target in this generator for what setting it from
// application code looks like. Kubernetes does not surface this field
// in any user-facing configuration; whatever crypto/tls negotiates by
// default is what ships. configs.js sets supportsCurveSelection:false
// to make that limitation explicit in the capability table. This also
// means Kubernetes does NOT inherit group preferences from openssl.cnf
// (Go's crypto/tls is a pure-Go implementation that ignores libssl
// configuration entirely); the only lever for ML-KEM hybrid key
// exchange is the Go runtime version Kubernetes was built with.
//
// Post-quantum hybrid groups (X25519MLKEM768) reach Kubernetes the same
// way: through the Go runtime the components were built with. Go 1.24
// (Feb 2025) added X25519MLKEM768 to crypto/tls's default group
// preference list; Kubernetes 1.34 (Aug 2025) was the first release
// built with Go 1.24 and is therefore the first release that negotiates
// ML-KEM hybrid key exchange out of the box. Operators on Go 1.24 / 1.25
// can still use the GODEBUG=tlsmlkem=0 kill-switch; on Go 1.26+ the
// kill-switch is expected to become a no-op. The Mozilla blog post above
// has the timeline.
//
// HSTS: kube-apiserver gained `--strict-transport-security-directives`
// in v1.28 (Aug 2023). configs.js encodes that as supportsHsts:'1.28.0'
// — earlier kube-apiservers and kubelet (which has no HSTS surface at
// any version) just silently drop the directive.
import minver from './minver.js';
import { safe } from './ctx.js';

export default (form, output) => {
  // Whether the running kube-apiserver supports
  // --strict-transport-security-directives. The kubelet itself never
  // does, but the rendered comment block targets both components.
  const apiserverHsts = form.hsts && minver('1.28.0', form.serverVersion);

  // Translate state.js's protocol token ('TLSv1' / 'TLSv1.1' / 'TLSv1.2'
  // / 'TLSv1.3') into Go's tls package constant naming, which is what
  // kube-apiserver and kubelet accept verbatim. 'TLSv1' (no .0 suffix —
  // see grid-axes.js / state.js conventions) maps to VersionTLS10.
  const minProto = output.protocols[0] === 'TLSv1'
    ? 'VersionTLS10'
    : output.protocols[0].replace('TLSv1.', 'VersionTLS1');

  // Per-template context (see ./ctx.js): every form.* value spliced
  // into the rendered config string is filtered through safe() as
  // defence in depth.
  const ctx = {
    serverVersion: safe(form.serverVersion),
  };

  // Header comment block. Names every directive emitted, cites the
  // upstream documentation, and explains the Go-runtime path for PQ.
  let conf =
       '# '+output.header+'\n'+
       '# '+output.link+'\n'+
       '#\n'+
       '# Kubernetes KubeletConfiguration snippet for the kubelet --config\n'+
       '# file, plus the equivalent kube-apiserver command-line flags as\n'+
       '# comments. Both surfaces accept the same TLS values; pick the\n'+
       '# one that matches the component you are configuring.\n'+
       '#\n'+
       '# Kubernetes components are Go binaries; TLS knobs that are NOT\n'+
       '# exposed via flags or KubeletConfiguration (notably the curve /\n'+
       '# group preference) are inherited from crypto/tls\'s defaults in\n'+
       '# the Go version Kubernetes was built with. See the "Go" target\n'+
       '# in this generator for what those defaults look like.\n'+
       '#\n';

  if (form.pq !== 'none') {
    conf +=
       '# Post-quantum (ML-KEM hybrid) key exchange:\n'+
       '#   Kubernetes does not expose Config.CurvePreferences; the\n'+
       '#   selected hybrid group reaches the wire only via the Go\n'+
       '#   runtime\'s default group list. Kubernetes 1.34 (Aug 2025) was\n'+
       '#   the first release built with Go 1.24, which added\n'+
       '#   X25519MLKEM768 to crypto/tls\'s default groups. On Go 1.24 /\n'+
       '#   1.25 the kill-switch is GODEBUG=tlsmlkem=0; on Go 1.26+ that\n'+
       '#   toggle is expected to become a no-op once ML-KEM is the\n'+
       '#   default.\n';
    if (!minver('1.34.0', form.serverVersion)) {
      conf +=
       '# WARNING: Kubernetes '+ctx.serverVersion+' was built with a Go\n'+
       '#          release earlier than 1.24 and therefore will not\n'+
       '#          negotiate X25519MLKEM768 by default. Upgrade to\n'+
       '#          Kubernetes 1.34 or newer (Go 1.24+) to enable PQ\n'+
       '#          hybrid key exchange via the Go runtime.\n';
    }
    if (form.pq === 'only') {
      conf +=
       '# NOTE: PQ-only mode (refuse classical-only key exchange) cannot\n'+
       '#       be expressed in Kubernetes today — neither via\n'+
       '#       KubeletConfiguration nor via kube-apiserver flags. The\n'+
       '#       rendered tlsMinVersion is pinned to VersionTLS13 (ML-KEM\n'+
       '#       hybrids are TLS 1.3-only) which is the strongest knob\n'+
       '#       Kubernetes exposes; the actual group selection is left\n'+
       '#       to crypto/tls. Track upstream proposals to expose\n'+
       '#       Config.CurvePreferences as a configuration field.\n';
    }
    conf +=
       '#\n';
  }

  conf +=
       'apiVersion: kubelet.config.k8s.io/v1beta1\n'+
       'kind: KubeletConfiguration\n'+
       'tlsMinVersion: '+minProto+'\n';

  if (output.ciphers.length) {
    // Go's crypto/tls treats CipherSuites as TLS 1.2-and-earlier-only;
    // TLS 1.3 cipher suites are not configurable. KubeletConfiguration
    // and kube-apiserver share that constraint, so emit only what
    // state.js put in output.ciphers (the IANA TLS 1.2 list for
    // intermediate / old; an empty list for modern, in which case we
    // skip the field entirely and let Go's TLS 1.3 defaults apply).
    conf +=
       'tlsCipherSuites:\n';
    for (let c of output.ciphers) {
      conf +=
       '- '+c+'\n';
    }
  }

  conf +=
       'tlsCertFile: /path/to/signed_cert_plus_intermediates\n'+
       'tlsPrivateKeyFile: /path/to/private_key\n'+
       '\n'+
       '# kube-apiserver equivalent flags (pass on the command line, or\n'+
       '# encode in the static-pod manifest under spec.containers[].command):\n'+
       '#   --tls-min-version='+minProto+'\n';

  if (output.ciphers.length) {
    conf +=
       '#   --tls-cipher-suites='+output.ciphers.join(',')+'\n';
  }

  conf +=
       '#   --tls-cert-file=/path/to/signed_cert_plus_intermediates\n'+
       '#   --tls-private-key-file=/path/to/private_key\n';

  if (form.hsts) {
    if (apiserverHsts) {
      conf +=
       '#   --strict-transport-security-directives=max-age='+output.hstsMaxAge+',includeSubDomains\n';
    }
    else {
      conf +=
       '#\n'+
       '# HSTS: --strict-transport-security-directives requires\n'+
       '# kube-apiserver v1.28.0 or newer; the running version\n'+
       '# ('+ctx.serverVersion+') is older and silently ignores the flag.\n'+
       '# Front kube-apiserver with an HSTS-aware reverse proxy (nginx,\n'+
       '# HAProxy, Caddy, …) to add the response header on older clusters.\n';
    }
  }

  return conf;
};
