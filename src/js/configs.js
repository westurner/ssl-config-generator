// configs for the supported pieces of software
//
// Capability-flag conventions
// ---------------------------
// Each `supports*` / `usesOpenssl` / `showSupports` / `hasVersions`
// flag accepts THREE shapes — and the rendered helpers capability table
// in src/templates/index.ejs (the one served at the bottom of the
// site) surfaces all three states explicitly:
//
//   - '<ver>'   → the first upstream release that surfaced the feature.
//                 The string is documentation-only; runtime gating in
//                 src/js/render.js coerces these flags to a boolean via
//                 `!!`, and `eolBefore` decides which historical
//                 versions are even selectable in the UI. The table
//                 displays the version string verbatim.
//   - true      → "supported, version unknown / not yet recorded".
//   - false     → not supported by this helper at all (table: "no").
//
// Every helper MUST declare an explicit value (true / false / version
// string) for every column rendered in the capability table — there
// are no longer any cells that fall back to a runtime default. The
// renderer's gating uses a simple `!!flag` truthy check (see the
// `hstsOn` / `usesOpenssl` sites in src/js/render.js); that's only safe
// because of this contract. Adding a new helper without all six
// capability flags will surface as a literal `—` in the table and is a
// bug — fix the configs.js entry, do not weaken the runtime gate.
//
// Per-flag semantics
// ------------------
// supportsPq answers the operator question "is this server even ABLE to
// negotiate post-quantum key exchange today?" — orthogonal to the
// per-curve / per-cipher mitigation-latency flags below. A helper opts
// IN by declaring it has a PQ-aware render branch today (X25519MLKEM768
// / SecP256r1MLKEM768 / SecP384r1MLKEM1024 codepoints, or a managed-
// policy alias like s2n-tls 'default_pq' that negotiates ML-KEM hybrids
// automatically). Helpers that have NO PQ surface whatsoever (no group
// token, no comment, no policy alias) MUST set this to `false`.
//   - supportsPq:'<ver>' → helper has a PQ-aware codepath in src/js/helpers/;
//                          the value is the first upstream release that
//                          surfaced PQ key exchange (mirrors how `tls13` and
//                          version-string `supportsOcspStapling` are
//                          encoded). Render.js exposes this verbatim on
//                          output.supportsPq.
//   - supportsPq:true    → also accepted (treated as "supports PQ, version
//                          unknown / not yet recorded").
//   - supportsPq:false   → no PQ surface; the helper ignores form.pq.
//
// supportsCipherSelection, supportsCurveSelection, and supportsHsts
// each accept the same value shapes as `supportsPq` /
// `supportsOcspStapling`:
//   - supportsCipherSelection:false  → the helper cannot emit a per-cipher list
//                                      (e.g. AWS ALB / s2n-tls / rustls expose
//                                      only named "policy" identifiers).
//   - supportsCurveSelection:false   → the helper cannot express a TLS named-group
//                                      / curve preference (e.g. MySQL, Tomcat,
//                                      Jetty, Redis, Squid, AWS ELB/ALB, s2n-tls,
//                                      rustls, the LiteSpeed family, Coturn,
//                                      OracleHTTP).
//   - supportsHsts:false             → not an HTTP server (Postfix, Dovecot,
//                                      OpenLDAP, Coturn, MySQL, …) — and the
//                                      helper does not emit any HSTS-related
//                                      artifact (header, redirect, etc.) when
//                                      form.hsts is set.
//
//   Why this matters (security): being able to specify ciphers / curves
//   explicitly in a server config is itself a security-hardening feature.
//   When a previously-trusted primitive is found broken or weakened
//   (Sweet32 against 3DES, the SLOTH attack against MD5/SHA-1 in TLS 1.2,
//   the 2024 announcements around classical ECDH parameters), an operator
//   running a server that exposes per-cipher / per-curve knobs can
//   mitigate IMMEDIATELY by editing one config file and reloading — they
//   don't have to wait for an upstream patch, a vendor advisory, or a new
//   binary release. Conversely, helpers marked supportsCipherSelection:false
//   or supportsCurveSelection:false (AWS ALB managed policies, s2n-tls
//   security policies, MySQL, Redis, Tomcat, …) bind the operator to the
//   vendor's update cadence: the only way to drop a freshly-broken
//   primitive is to wait for the vendor to ship a new managed-policy
//   identifier or a new server build. The capability flags here document
//   that limitation explicitly so the UI can surface it and so operators
//   making procurement decisions can weigh "fast mitigation latency" as
//   one of the criteria.
//
// cipherFormat is assumed to be 'openssl' unless defined otherwise


module.exports = {
  apache: {
    latestVersion: '2.4.60',
    eolBefore: '2.4.0',
    name: 'Apache',
    // mod_ssl is built on OpenSSL.
    usesOpenssl: true,
    // SSLCipherSuite shipped with mod_ssl in Apache httpd 2.0.0 — the
    // initial release of the 2.x series (the original merge of mod_ssl
    // into the httpd tree).
    supportsCipherSelection: '2.0.0',
    // SSLOpenSSLConfCmd Curves landed in Apache httpd 2.4.7
    // (mod_ssl, Nov 2013); see helpers/apache.js:68
    // (`minver("2.4.11", form.serverVersion)` for the directive choice and
    // CHANGES_2.4 for the original `SSLOpenSSLConfCmd` introduction in
    // 2.4.7). Earlier 2.x had only the implicit OpenSSL default group list.
    supportsCurveSelection: '2.4.7',
    // mod_headers `Header always set` was introduced in Apache httpd 2.0;
    // see helpers/apache.js:60. (HSTS itself is just an HTTP response
    // header, mod_headers is what emits it.)
    supportsHsts: '2.0.0',
    supportsOcspStapling: '2.4.13',
    // No PQ-aware code path in src/js/helpers/apache.js today; PQ key
    // exchange depends on the linked OpenSSL but the helper does not
    // emit a hybrid-group token or PQ comment.
    supportsPq: false,
    tls13: '2.4.36',
  },
  awsalb: {
    hasVersions: false,
    latestVersion: '2023.3.22',
    name: 'AWS ALB',
    showSupports: false,
    supportsCipherSelection: false,
    supportsCurveSelection: false,
    // ALB has no native HSTS header knob, but the helper renders a
    // separate HTTP→HTTPS redirect listener when form.hsts is set
    // (helpers/awsalb.js:4-25); that's the closest ALB-native artifact
    // to "operator opted into HSTS", so keep this true so the toggle
    // remains user-visible.
    supportsHsts: true,
    supportsOcspStapling: false,
    // ALB managed policies do not yet expose a hybrid-PQ option.
    supportsPq: false,
    tls13: '2023.3.22',
    usesOpenssl: false,
  },
  // supported ciphers generated with:
  // aws elb describe-load-balancer-policies --query "PolicyDescriptions[?PolicyName=='ELBSample-ELBDefaultCipherPolicy'].PolicyAttributeDescriptions[*].AttributeName[]"
  awselb: {
    hasVersions: false,
    latestVersion: '2014.2.19',
    name: 'AWS ELB',
    supportedCiphers: ['ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA', 'DHE-RSA-AES128-SHA', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA', 'ECDHE-ECDSA-AES256-SHA', 'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA', 'DHE-DSS-AES128-SHA', 'CAMELLIA128-SHA', 'EDH-RSA-DES-CBC3-SHA', 'DES-CBC3-SHA', 'ECDHE-RSA-RC4-SHA', 'RC4-SHA', 'ECDHE-ECDSA-RC4-SHA', 'DHE-DSS-AES256-GCM-SHA384', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA256', 'DHE-DSS-AES256-SHA256', 'DHE-RSA-AES256-SHA', 'DHE-DSS-AES256-SHA', 'DHE-RSA-CAMELLIA256-SHA', 'DHE-DSS-CAMELLIA256-SHA', 'CAMELLIA256-SHA', 'EDH-DSS-DES-CBC3-SHA', 'DHE-DSS-AES128-GCM-SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-SHA256', 'DHE-DSS-AES128-SHA256', 'DHE-RSA-CAMELLIA128-SHA', 'DHE-DSS-CAMELLIA128-SHA', 'ADH-AES128-GCM-SHA256', 'ADH-AES128-SHA', 'ADH-AES128-SHA256', 'ADH-AES256-GCM-SHA384', 'ADH-AES256-SHA', 'ADH-AES256-SHA256', 'ADH-CAMELLIA128-SHA', 'ADH-CAMELLIA256-SHA', 'ADH-DES-CBC3-SHA', 'ADH-DES-CBC-SHA', 'ADH-RC4-MD5', 'ADH-SEED-SHA', 'DES-CBC-SHA', 'DHE-DSS-SEED-SHA', 'DHE-RSA-SEED-SHA', 'EDH-DSS-DES-CBC-SHA', 'EDH-RSA-DES-CBC-SHA', 'IDEA-CBC-SHA', 'RC4-MD5', 'SEED-SHA', 'DES-CBC3-MD5', 'DES-CBC-MD5', 'RC2-CBC-MD5', 'PSK-AES256-CBC-SHA', 'PSK-3DES-EDE-CBC-SHA', 'KRB5-DES-CBC3-SHA', 'KRB5-DES-CBC3-MD5', 'PSK-AES128-CBC-SHA', 'PSK-RC4-SHA', 'KRB5-RC4-SHA', 'KRB5-RC4-MD5', 'KRB5-DES-CBC-SHA', 'KRB5-DES-CBC-MD5', 'EXP-EDH-RSA-DES-CBC-SHA', 'EXP-EDH-DSS-DES-CBC-SHA', 'EXP-ADH-DES-CBC-SHA', 'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5', 'EXP-KRB5-RC2-CBC-SHA', 'EXP-KRB5-DES-CBC-SHA', 'EXP-KRB5-RC2-CBC-MD5', 'EXP-KRB5-DES-CBC-MD5', 'EXP-ADH-RC4-MD5', 'EXP-RC4-MD5', 'EXP-KRB5-RC4-SHA', 'EXP-KRB5-RC4-MD5'],
    // ELB exposes a per-cipher allowlist via the SSLNegotiationPolicyType
    // PolicyAttributes (see helpers/awselb.js:14-22).
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // Classic ELB does not support OCSP stapling.
    supportsOcspStapling: false,
    // No PQ-capable named cipher policy on Classic ELB.
    supportsPq: false,
    usesOpenssl: false,
  },
  caddy: {
    cipherFormat: 'go',
    latestVersion: '2.8.4',
    eolBefore: '2.0.0',
    name: 'Caddy',
    // The Caddy v2 rewrite (Caddy 2.0.0, May 2020) introduced the
    // tls.cipher_suites, tls.curves, and `header` directives the helper
    // emits; see helpers/caddy.js:8 (`if (!minver("2.0.0", ...))` bail
    // out). Caddy 1.x used a completely different config language.
    supportsCipherSelection: '2.0.0',
    supportsCurveSelection: '2.0.0',
    supportsHsts: '2.0.0',
    // Caddy automatically manages OCSP stapling out-of-band; no
    // operator-tunable stapling directive is emitted by helpers/caddy.js.
    supportsOcspStapling: false,
    // Caddy 2.10.0 (Apr 2025) shipped support for the standardised
    // X25519MLKEM768 hybrid PQ group by default. Earlier 2.x had only
    // experimental Kyber drafts via Go's crypto/tls.
    supportsPq: '2.10.0',
    tls13: '0.11.5',
    usesOpenssl: false,
  },
  coturn: {
    latestVersion: '4.6.2',
    name: 'Coturn',
    showSupports: false,
    // coturn links libssl/libcrypto for DTLS/TLS.
    usesOpenssl: true,
    // helpers/coturn.js:13 emits `cipher-list=...` from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // No `cert-staple` / OCSP directive in helpers/coturn.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '4.6.2',
  },
  dovecot: {
    latestVersion: '2.4.2',
    eolBefore: '2.2.36', // https://dovecot.org/list/dovecot/2018-August/112536.html
    name: 'Dovecot',
    showSupports: false,
    // Dovecot links OpenSSL for its TLS implementation.
    usesOpenssl: true,
    // ssl_cipher_list (renamed to ssl_cipher_suites in 2.4) has been a
    // documented Dovecot directive since the 2.0 series; helpers/dovecot.js:43
    // emits it from output.ciphers.
    supportsCipherSelection: true,
    supportsHsts: false,
    // ssl_curve_list (renamed to ssl_curves in 2.4) was added in Dovecot
    // 2.2.6 (Jul 2014). Earlier 2.2.x had no per-curve knob and used
    // OpenSSL's compiled-in default group preference.
    supportsCurveSelection: '2.2.6',
    // No OCSP-stapling directive in helpers/dovecot.js.
    supportsOcspStapling: false,
    // No PQ-aware code path; PQ key exchange depends on linked OpenSSL
    // but the helper does not emit a hybrid-group token or comment.
    supportsPq: false,
    tls13: '2.3.15',
  },
  exim: {
    latestVersion: '4.98',
    eolBefore: '4.98',
    name: 'Exim',
    showSupports: false,
    // Exim's TLS layer is OpenSSL (or GnuTLS at build time); helpers/exim.js
    // assumes the OpenSSL build (openssl_options).
    usesOpenssl: true,
    // helpers/exim.js:23 emits `tls_require_ciphers = ...` from
    // output.ciphers; this directive has been part of Exim's TLS support
    // since the early 4.x series.
    supportsCipherSelection: true,
    // Exim is a mail server (no HTTP layer); HSTS does not apply.
    supportsHsts: false,
    // tls_eccurve was added in Exim 4.80 (May 2012) for the GnuTLS build
    // and extended to OpenSSL builds with the helper-noted gate of
    // 4.97 + OpenSSL 1.1.1 (helpers/exim.js:17). The capability statement
    // is "first upstream release that surfaced the directive".
    supportsCurveSelection: '4.80',
    // No OCSP-stapling directive emitted by helpers/exim.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '4.92.0',
  },
  go: {
    cipherFormat: 'go',
    latestVersion: '1.23.3',
    eolBefore: '1.22.0',
    name: 'Go',
    // crypto/tls.Config.CipherSuites and CurvePreferences were both added
    // in Go 1.5 (Aug 2015); see the Go 1.5 release notes
    // (https://go.dev/doc/go1.5#crypto_tls). Earlier Go negotiated whatever
    // the implementation chose internally with no per-suite / per-curve
    // knob.
    supportsCipherSelection: '1.5.0',
    supportsCurveSelection: '1.5.0',
    // helpers/go.js:20-23 writes the Strict-Transport-Security response
    // header from Go application code when form.hsts is set.
    supportsHsts: true,
    // No crypto/tls API for OCSP stapling is used by helpers/go.js;
    // applications would have to wire it up themselves.
    supportsOcspStapling: false,
    // Go 1.24 (Feb 2025) added X25519MLKEM768 to crypto/tls and enabled
    // it in the default group preference list.
    supportsPq: '1.24.0',
    tls13: '1.13.0',
    usesOpenssl: false,
    supportedCiphers: [ 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256' ],
  },
  gnutls: {
    latestVersion: '3.8.10',
    eolBefore: '3.8.0',
    name: 'GnuTLS',
    showSupports: false,
    // helpers/gnutls.js:88-100 emits +AES-128-GCM/+AES-256-GCM/
    // +CHACHA20-POLY1305 (and legacy CBC tokens for the "old" profile)
    // as part of the priority string.
    supportsCipherSelection: true,
    // helpers/gnutls.js:54-81 emits +GROUP-* tokens (GROUP-X25519,
    // GROUP-SECP256R1, ...) from output.tlsCurves.
    supportsCurveSelection: true,
    supportsHsts: false,
    // No OCSP-stapling token emitted by helpers/gnutls.js.
    supportsOcspStapling: false,
    // GnuTLS 3.8.10 (Mar 2025) added the GROUP-X25519-MLKEM768 hybrid
    // group; gated by minver('3.8.10', ...) in src/js/helpers/gnutls.js.
    supportsPq: '3.8.10',
    tls13: '3.6.4',
    usesOpenssl: false,
    // GnuTLS 3.8.10 added the X25519-MLKEM768 hybrid PQ group.
  },
  haproxy: {
    latestVersion: '3.0',
    eolBefore: '2.2',
    name: 'HAProxy',
    // HAProxy links OpenSSL for its TLS layer.
    usesOpenssl: true,
    // ssl-default-bind-ciphers / -ciphersuites in the global section
    // landed in HAProxy 1.5 (Jun 2014); see helpers/haproxy.js:5
    // (`if (!minver("1.5.0", ...))` bail-out: the entire SSL section
    // requires 1.5+).
    supportsCipherSelection: '1.5.0',
    // ssl-default-bind-curves / ssl-default-server-curves were added in
    // HAProxy 2.9 (Dec 2023); see helpers/haproxy.js:11
    // (`minver("2.9.0", form.serverVersion)`). Earlier versions could
    // only set `curves` on a per-bind basis.
    supportsCurveSelection: '2.9.0',
    // `http-response set-header Strict-Transport-Security ...` requires
    // HAProxy 1.5+ (the `http-response` ruleset family arrived with the
    // 1.5 SSL/HTTP overhaul).
    supportsHsts: '1.5.0',
    // HAProxy stapling works via an external OCSP response file: place
    // <crt>.ocsp (DER-encoded OCSP response) alongside the certificate
    // file referenced by `bind ... crt /path/to/<cert>`. HAProxy 1.6+
    // discovers the file at startup and serves it as a stapled response;
    // 1.7+ allows runtime refresh via `set ssl ocsp-response` over the
    // admin socket; 2.8+ adds a built-in auto-updater
    // (`tune.ssl.ocsp-update.mode on`). The helper emits an explanatory
    // comment block (no directive needed for the file-discovery path).
    supportsOcspStapling: '1.6.0',
    // PQ key exchange piggybacks on the OpenSSL `Groups` list emitted via
    // `ssl-default-bind-curves` / `ssl-default-server-curves` (HAProxy
    // 2.9+). When form.pq !== 'none' those curves include the ML-KEM
    // hybrid groups (X25519MLKEM768 et al.); the linked OpenSSL must be
    // ≥ 3.5.0 to recognise the names natively (older OpenSSL needs the
    // oqs-provider). The helper emits a `# WARNING:` block when HAProxy
    // < 2.9 (no curves directive available) or OpenSSL < 3.5.
    supportsPq: '2.9.0',
    tls13: '1.8.0',
  },
  iis: {
    cipherFormat: 'iana',
    latestVersion: '10.0.26100', // Windows Server 2025 / Win 11 24H2
    eolBefore: '10.0.17763',     // pre-Server 2019 builds are unsupported
    name: 'IIS (PowerShell)',
    // The `Functions` REG_SZ cipher-suite-ordering value (the only
    // operator-tunable cipher / curve knob in Schannel) is documented
    // since Windows 10 1507 / Server 2016 (build 10.0.10240); the
    // `EccCurves` REG_MULTI_SZ shipped at the same time.
    supportsCipherSelection: '10.0.10240',
    supportsCurveSelection: '10.0.10240',
    // The IIS 10 native `<hsts>` element configured by the helper via
    // `Set-WebConfigurationProperty` was added in IIS 10.0 v1709
    // (Windows 10 v1709 / Windows Server, version 1709, build
    // 10.0.16299); see helpers/iis.js:26-28.
    supportsHsts: '10.0.16299',
    // Schannel handles OCSP stapling automatically; helpers/iis.js does
    // not emit any operator-tunable stapling directive.
    supportsOcspStapling: false,
    // Hybrid ML-KEM in Schannel/SymCrypt is exposed on Windows Server
    // 2025 / Win 11 24H2 (Insider builds) — first build numbered
    // 10.0.26100; group string MLKEM768X25519.
    supportsPq: '10.0.26100',
    tls13: '10.0.20348',         // Server 2022 / Win 11; first Schannel build with TLS 1.3 enabled by default
    usesOpenssl: false,
    // IIS uses Schannel (not OpenSSL). The helper emits a PowerShell script
    // that backs up the existing SCHANNEL/cipher-policy registry keys to a
    // .reg file via `reg.exe export` and supports a `-Restore` switch to
    // re-import the backup. Hybrid PQ key exchange (X25519MLKEM768, named
    // `MLKEM768X25519` in Schannel) is available on Windows Server 2025 /
    // Windows 11 24H2 preview builds; the script surfaces it for `pq=only`.
  },
  jetty: {
    cipherFormat: 'iana',
    latestVersion: '12.0.15',
    eolBefore: '12.0.0',
    name: 'Jetty',
    // helpers/jetty.js:31-41 emits an IncludeCipherSuites array.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // No OCSP-stapling element emitted by helpers/jetty.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '9.4.12',
    usesOpenssl: false,
  },
  kubernetes: {
    cipherFormat: 'go',
    latestVersion: '1.34.0',
    eolBefore: '1.32.0',
    name: 'Kubernetes',
    // Kubernetes components (kube-apiserver, kubelet, kube-controller-
    // manager, kube-scheduler, kube-proxy) are Go binaries built against
    // crypto/tls; they have no separate TLS implementation. usesOpenssl
    // is therefore false for the same reason it's false for go.
    usesOpenssl: false,
    // helpers/kubernetes.js emits tlsCipherSuites: (in YAML) and
    // --tls-cipher-suites= (as a comment), both consuming Go's IANA
    // cipher names. KubeletConfiguration / kube-apiserver have accepted
    // the field since at least v1.10 (when KubeletConfiguration was
    // introduced); older versions used flags only — still supported.
    supportsCipherSelection: true,
    // No `--tls-curve-preferences` / `tlsCurvePreferences` knob exists
    // in Kubernetes today — kube-apiserver and kubelet inherit whatever
    // crypto/tls negotiates by default. The capability table surfaces
    // this so operators don't expect a per-curve mitigation knob.
    supportsCurveSelection: false,
    // kube-apiserver gained --strict-transport-security-directives in
    // v1.28 (Aug 2023) — see the Kubernetes 1.28 release notes /
    // command-line reference. kubelet has no HSTS surface at any
    // version; helpers/kubernetes.js emits the apiserver flag as a
    // comment when form.hsts is set on a 1.28+ cluster, and emits a
    // "front with a reverse proxy" note on older versions.
    supportsHsts: '1.28.0',
    // Kubernetes does not surface OCSP stapling: neither kube-apiserver
    // nor kubelet wires SSL_CTX_set_tlsext_status_cb-equivalents
    // through its config, and crypto/tls itself doesn't ship a
    // production stapler. Front the apiserver with a TLS-terminating
    // reverse proxy (nginx, HAProxy, Caddy) for stapling.
    supportsOcspStapling: false,
    // PQ readiness is inherited from the Go runtime Kubernetes was
    // built with (see helpers/kubernetes.js header). Kubernetes 1.34
    // (Aug 2025) was the first release built with Go 1.24, the first
    // Go release that added X25519MLKEM768 to crypto/tls's default
    // group preference list — so 1.34 is the first Kubernetes that
    // negotiates ML-KEM hybrid key exchange out of the box. See the
    // "Post-Quantum Cryptography in Kubernetes" blog post (k8s-pqc-blog
    // in citations.bib).
    supportsPq: '1.34.0',
    // kube-apiserver --tls-min-version=VersionTLS13 has been accepted
    // since v1.16 (when --tls-min-version itself was promoted out of
    // alpha alongside the feature gate that exposed Go 1.12's TLS 1.3
    // implementation).
    tls13: '1.16.0',
  },
  lighttpd: {
    latestVersion: '1.4.82',
    eolBefore: '1.4.69',
    name: 'lighttpd',
    // helpers/lighttpd.js targets the mod_openssl backend by default.
    usesOpenssl: true,
    // helpers/lighttpd.js:83/87 emits ssl.openssl.ssl-conf-cmd
    // ("CipherString" => …) (or the legacy ssl.cipher-list) from
    // output.ciphers.
    supportsCipherSelection: true,
    // helpers/lighttpd.js:64 emits ssl.openssl.ssl-conf-cmd ("Curves" => …)
    // from output.tlsCurves on lighttpd 1.4.50+ (when ssl-conf-cmd was
    // introduced).
    supportsCurveSelection: '1.4.50',
    // helpers/lighttpd.js:174-202 emits HSTS via mod_setenv /
    // mod_redirect; both modules have been part of the lighttpd 1.4
    // series for many releases, but the exact first version isn't
    // tracked here — declared as `true` ("supported, version
    // unknown") rather than a version string.
    supportsHsts: true,
    supportsOcspStapling: '1.4.56',
    // helpers/lighttpd.js:64 emits ssl.openssl.ssl-conf-cmd ("Curves" => …)
    // from output.tlsCurves on lighttpd 1.4.50+ (when ssl-conf-cmd was
    // introduced). When form.pq !== 'none' those tlsCurves include the
    // ML-KEM hybrid groups (X25519MLKEM768 et al.); the underlying
    // OpenSSL must be ≥ 3.5.0 to recognise the names natively (older
    // OpenSSL needs the oqs-provider). The helper emits a `# WARNING:`
    // block when OpenSSL < 3.5.0 so the operator sees the dependency.
    supportsPq: '1.4.50',
    tls13: '1.4.48',
  },
  litespeed: {
    latestVersion: '6.3.5',
    eolBefore: '5.4.12',
    name: 'LiteSpeed',
    // LiteSpeed Web Server uses OpenSSL.
    usesOpenssl: true,
    // helpers/litespeed.js:22 emits `ciphers ...` from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    // helpers/litespeed.js:46-53 emits an HSTS Header in a `context`
    // block when form.hsts is set.
    supportsHsts: true,
    supportsOcspStapling: '1.2',
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '5.4.12',
  },
  mysql: {
    latestVersion: '9.1.0',
    eolBefore: '8.0.0',
    name: 'MySQL',
    showSupports: false,
    // MySQL builds against OpenSSL (or YaSSL/wolfSSL historically).
    usesOpenssl: true,
    // helpers/mysql.js:13 emits `ssl-cipher = ...` from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // No OCSP-stapling directive in helpers/mysql.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '8.0.16',
  },
  nginx: {
    latestVersion: '1.27.3',
    eolBefore: '1.26.0',
    name: 'nginx',
    // nginx links OpenSSL for its TLS layer.
    usesOpenssl: true,
    // helpers/nginx.js:42-46 emits `ssl_ciphers ...` from output.ciphers
    // (directive present since the early 0.x ngx_http_ssl_module).
    supportsCipherSelection: true,
    // helpers/nginx.js:41 emits `ssl_ecdh_curve ...` from
    // output.tlsCurves; the directive has been part of nginx for a very
    // long time.
    supportsCurveSelection: true,
    // The `always` parameter on `add_header` (used by the helper to emit
    // HSTS so the header is set on error responses too) was added in
    // nginx 1.7.5; see helpers/nginx.js:33. Earlier nginx supported
    // `add_header` since 0.5.x but only on 2xx/3xx responses, which is
    // unsafe for HSTS (RFC 6797 §7.2 requires the header on every
    // response over a secure transport).
    supportsHsts: '1.7.5',
    supportsOcspStapling: '1.3.7',
    // No PQ-aware code path; PQ key exchange depends on linked OpenSSL
    // but the helper does not emit a hybrid-group token or PQ comment.
    supportsPq: false,
    tls13: '1.13.0',
  },
  openssl: {
    latestVersion: '3.6.1',
    eolBefore: '3.0.0',
    tls13: '1.1.1',
  },
  opensslcnf: {
    latestVersion: '3.6.1',
    eolBefore: '3.0.0',
    name: 'OpenSSL config (openssl.cnf)',
    showSupports: false,
    // openssl.cnf is OpenSSL's own configuration file.
    usesOpenssl: true,
    // helpers/opensslcnf.js:79-88 emits CipherString / Ciphersuites from
    // output.ciphers / output.cipherSuites; SSL_CONF "CipherString" /
    // "Ciphersuites" have been the canonical openssl.cnf cipher knobs
    // since the SSL_CONF API was introduced in OpenSSL 1.0.2 / 1.1.0.
    supportsCipherSelection: true,
    supportsHsts: false,
    // The `Groups` SSL_CONF command (the openssl.cnf form of
    // `-groups`/`SSL_CONF_cmd("Groups", ...)`) was added in OpenSSL 1.1.1
    // when the named-group preference list replaced the older
    // `Curves` command for TLS 1.3.
    supportsCurveSelection: '1.1.1',
    // openssl.cnf has no per-application OCSP-stapling switch (stapling
    // is wired up by each application that calls SSL_CTX_set_tlsext_*).
    supportsOcspStapling: false,
    // OpenSSL 3.5.0 (Apr 2025) shipped built-in ML-KEM hybrid groups
    // (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024); gated by
    // minver('3.5.0', form.opensslVersion) in src/js/helpers/opensslcnf.js.
    supportsPq: '3.5.0',
    tls13: '1.1.1',
    // openssl.cnf is read by every OpenSSL-based application, including
    // Python's `ssl` module (which honours system openssl.cnf), curl, etc.
  },
  openlitespeed: {
    latestVersion: '1.8.5',
    eolBefore: '1.4.35',
    name: 'OpenLiteSpeed',
    // OpenLiteSpeed uses OpenSSL.
    usesOpenssl: true,
    // helpers/openlitespeed.js:33 emits `<ciphers>...` from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    // helpers/openlitespeed.js:46-58 emits HSTS via `<extraHeaders>`.
    supportsHsts: true,
    supportsOcspStapling: '1.2',
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '1.4.35',
  },
  openldap: {
    latestVersion: '2.6.9',
    eolBefore: '2.6.0',
    name: 'OpenLDAP (slapd)',
    showSupports: false,
    // slapd links the system's OpenSSL (or GnuTLS at build time);
    // helpers/openldap.js targets the OpenSSL build.
    usesOpenssl: true,
    // helpers/openldap.js emits `TLSCipherSuite ...` for the TLSv1.2
    // and earlier cipher list.
    supportsCipherSelection: true,
    supportsHsts: false,
    supportsOcspStapling: false,
    // TLSECName (slapd.conf) / olcTLSECName (cn=config) was added in
    // OpenLDAP 2.4.36 (Nov 2013); earlier 2.4 had no operator-tunable
    // curve / group knob and used OpenSSL's compiled-in default.
    supportsCurveSelection: '2.4.36',
    // OpenLDAP delegates ML-KEM to its TLS backend (built-in hybrid groups
    // require OpenSSL >= 3.5.0). The 2.6 series is the supported baseline
    // that links cleanly with modern OpenSSL.
    supportsPq: '2.6.0',
    // OpenLDAP delegates TLS 1.3 to its TLS backend (OpenSSL 1.1.1+ or
    // GnuTLS 3.6+). 2.4.46 was the first 2.4.x to compile cleanly against
    // OpenSSL 1.1.1; the 2.5 series made it the supported baseline.
    tls13: '2.4.46',
    // OpenLDAP's TLS directives (TLSCipherSuite, TLSProtocolMin, TLSECName,
    // ...) are passed through to the linked OpenSSL/GnuTLS, so PQ readiness
    // is gated by the OpenSSL version: built-in ML-KEM hybrid groups (e.g.
    // X25519MLKEM768) require OpenSSL >= 3.5.0. TLSv1.3 ciphersuites are
    // NOT settable via slapd directives — they come from the system
    // openssl.cnf [system_default_sect] Ciphersuites line.
  },
  oraclehttp: {
    cipherFormat: 'iana',
    latestVersion: '12.2.1',
    name: 'Oracle HTTP',
    // helpers/oraclehttp.js:35 emits `SSLCipherSuite ...` from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    // helpers/oraclehttp.js:23-27 emits the Strict-Transport-Security
    // header when form.hsts is set.
    supportsHsts: true,
    // Oracle HTTP Server 12.2.1 (12cR2, Oct 2015) was the first release
    // to ship `SSLOCSPEnable` and the related Oracle-mod_ossl OCSP
    // stapling directives; see helpers/oraclehttp.js:36
    // (`minver("12.2.1", form.serverVersion)`).
    supportsOcspStapling: '12.2.1',
    // No PQ-aware code path.
    supportsPq: false,
    usesOpenssl: false,
  },
  postfix: {
    latestVersion: '3.9.0',
    eolBefore: '3.6.0',
    name: 'Postfix',
    showSupports: false,
    // Postfix builds against OpenSSL.
    usesOpenssl: true,
    // helpers/postfix.js:42 emits `tls_medium_cipherlist = ...` from
    // output.ciphers; the `tls_medium_cipherlist` knob has been part of
    // Postfix since the early 2.x SMTPS support.
    supportsCipherSelection: true,
    supportsHsts: false,
    // tls_eecdh_auto_curves was added in Postfix 3.4.0 (Feb 2019); see
    // helpers/postfix.js:14 (`minver("3.4.0", form.serverVersion)`).
    // Earlier Postfix could only set a single named curve via
    // smtpd_tls_eecdh_grade + tls_eecdh_strong_curve / _ultra_curve.
    supportsCurveSelection: '3.4.0',
    // No OCSP-stapling directive emitted by helpers/postfix.js.
    supportsOcspStapling: false,
    // No PQ-aware code path; PQ key exchange depends on the linked
    // OpenSSL but Postfix does not emit a hybrid-group token.
    supportsPq: false,
    tls13: '3.3.2',
  },
  postgresql: {
    latestVersion: '17.2',
    eolBefore: '13.0',
    name: 'PostgreSQL',
    showSupports: false,
    // PostgreSQL builds against OpenSSL.
    usesOpenssl: true,
    // helpers/postgresql.js:24 emits `ssl_ciphers = ...` from
    // output.ciphers; ssl_ciphers has been a server GUC for many
    // PostgreSQL major releases, but the exact first version isn't
    // tracked here — declared as `true` ("supported, version
    // unknown") rather than a version string.
    supportsCipherSelection: true,
    supportsHsts: false,
    // ssl_groups (the per-server TLS named-group preference list) was
    // added in PostgreSQL 18.0; see helpers/postgresql.js:18
    // (`minver("18.0.0", form.serverVersion)`). PostgreSQL 13–17 had only
    // ssl_ecdh_curve (single curve, ECDHE-only) — captured implicitly by
    // the helper's fallback emit; the capability flag here documents the
    // first release with a true preference-list directive.
    supportsCurveSelection: '18.0.0',
    // No OCSP-stapling directive in helpers/postgresql.js.
    supportsOcspStapling: false,
    // No PQ-aware code path; PQ key exchange depends on the linked
    // OpenSSL but PostgreSQL does not emit a hybrid-group token.
    supportsPq: false,
    tls13: '12.0',
  },
  proftpd: {
    latestVersion: '1.3.8',
    eolBefore: '1.3.8',  // http://www.proftpd.org/docs/howto/Versioning.html
    name: 'ProFTPD',
    showSupports: false,
    // ProFTPD's mod_tls links OpenSSL.
    usesOpenssl: true,
    // helpers/proftpd.js:39 emits `TLSCipherSuite ...` from output.ciphers.
    supportsCipherSelection: true,
    // helpers/proftpd.js:34 emits `TLSECDHCurve ...` from
    // output.tlsCurves when OpenSSL >= 1.0.2; the directive has been
    // part of mod_tls for many 1.3.x releases, but the exact first
    // version isn't tracked here — declared as `true` ("supported,
    // version unknown") rather than a version string.
    supportsCurveSelection: true,
    supportsHsts: false,
    supportsOcspStapling: '1.3.6',
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '1.3.7',
  },
  python: {
    latestVersion: '3.13.1',
    eolBefore: '3.10.0',
    name: 'Python (ssl module)',
    showSupports: false,
    supportsHsts: false,
    // SSLContext.set_ciphers() was added in Python 3.2; SSLContext itself
    // and per-context cipher selection arrived in 3.2 (Feb 2011) so this
    // is the floor for cipher selection.
    supportsCipherSelection: '3.2.0',
    // SSLContext.set_ecdh_curve() was added in Python 3.3 (Sep 2012).
    // SSLContext.set_groups() (multi-group preference list incl.
    // X25519MLKEM768) was added in 3.13 — captured by supportsPq below.
    supportsCurveSelection: '3.3.0',
    // Python 3.13 (Oct 2024) added SSLContext.set_groups(), which the
    // helper uses to pass X25519MLKEM768 et al. as a multi-group preference
    // list; older 3.x can only pin a single classical curve via
    // set_ecdh_curve(). The underlying OpenSSL must still be >= 3.5 for
    // built-in ML-KEM hybrids.
    supportsPq: '3.13.0',
    // Python's `ssl` module does not expose an OCSP-stapling API; OCSP
    // verification has to be wired by the application or its OpenSSL.
    supportsOcspStapling: false,
    tls13: '3.7.0',
    usesOpenssl: true,
    // Python's ssl module wraps OpenSSL. SSLContext.set_groups() (multi-
    // group preference list incl. X25519MLKEM768) was added in Python
    // 3.13; older 3.x can pin a single curve via set_ecdh_curve(). The
    // underlying OpenSSL must be 3.5+ for built-in ML-KEM hybrids.
  },
  redis: {
    latestVersion: '7.4.1',
    eolBefore: '7.4.0',
    name: 'Redis',
    showSupports: false,
    // Redis 6+ uses OpenSSL for TLS.
    usesOpenssl: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // Redis 6.0.0 (Apr 2020) was the first release with built-in TLS
    // support and the `tls-ciphers` / `tls-ciphersuites` config
    // directives; see helpers/redis.js:40 (`!minver("6.0", ...)` bail
    // out — the entire TLS config is gated on Redis 6+).
    supportsCipherSelection: '6.0.0',
    // No OCSP-stapling directive in helpers/redis.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '6.0',
  },
  rust: {
    cipherFormat: 'iana',
    latestVersion: '0.23.18',
    eolBefore: '0.23.0',
    name: 'Rust (rustls)',
    showSupports: false,
    // rustls cipher suites are not user-tunable; the chosen
    // CryptoProvider (aws-lc-rs / ring) picks them.
    supportsCipherSelection: false,
    supportsCurveSelection: false,
    supportsHsts: false,
    // rustls performs OCSP-stapled certificate verification on the
    // client side automatically; helpers/rust.js does not expose a
    // server-side stapling toggle.
    supportsOcspStapling: false,
    // rustls 0.23.18 (Nov 2024, with the aws-lc-rs provider) negotiates
    // X25519MLKEM768 automatically when both peers support it.
    supportsPq: '0.23.18',
    tls13: '0.20.0',
    usesOpenssl: false,
    // rustls 0.23.18 (aws-lc-rs provider) negotiates X25519MLKEM768.
  },
  s2n: {
    latestVersion: '1.7.2',
    eolBefore: '1.5.0',
    name: 's2n-tls',
    showSupports: false,
    supportsCipherSelection: false,
    supportsCurveSelection: false,
    supportsHsts: false,
    // s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP) has
    // been part of the public API since the very first releases.
    supportsOcspStapling: '1.0.0',
    // First s2n release with TLS 1.3 enabled by default in the named policies
    // ("default_tls13" was introduced in the v1.0.0 series; TLS 1.3 support
    // landed in security policy "20190801").
    tls13: '1.0.0',
    // s2n-tls 1.5.0 introduced the stable "default_pq" named policy alias
    // (X25519MLKEM768 hybrid); see PQ_MIN_VERSION in src/js/helpers/s2n.js.
    supportsPq: '1.5.0',
    usesOpenssl: false,
    // s2n-tls is configured via named security policies passed to
    // s2n_config_set_cipher_preferences(); cipher / curve lists are not
    // user-tunable. default_pq adds X25519MLKEM768 hybrid PQ key exchange.
  },
  squid: {
    latestVersion: '6.12',
    eolBefore: '6.0',
    name: 'Squid',
    showSupports: false,
    // Squid links OpenSSL.
    usesOpenssl: true,
    // helpers/squid.js:14-17 emits `cipher=...` (or `tls-cipher=...`)
    // from output.ciphers.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    supportsHsts: false,
    // No OCSP-stapling directive in helpers/squid.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '4',
  },
  stunnel: {
    latestVersion: '5.73',
    name: 'stunnel',
    // stunnel links OpenSSL.
    usesOpenssl: true,
    // helpers/stunnel.js:35 emits `ciphers = ...` from output.ciphers.
    supportsCipherSelection: true,
    // helpers/stunnel.js:30 emits `curves = ...` from output.tlsCurves
    // when OpenSSL >= 1.1.1.
    supportsCurveSelection: '1.1.1',
    supportsHsts: false,
    // No OCSP-stapling directive in helpers/stunnel.js.
    supportsOcspStapling: false,
    // No PQ-aware code path.
    supportsPq: false,
    tls13: '5.50',
  },
  tomcat: {
    latestVersion: '11.0.1',
    eolBefore: '9.0.0',
    name: 'Tomcat',
    // helpers/tomcat.js:67-71 emits `ciphers="…"` from output.ciphers /
    // output.cipherSuites.
    supportsCipherSelection: true,
    supportsCurveSelection: false,
    // helpers/tomcat.js:8-55 emits Tomcat's HttpHeaderSecurityFilter
    // (org.apache.catalina.filters.HttpHeaderSecurityFilter) which was
    // added in Tomcat 8.5.0 and emits Strict-Transport-Security from
    // hstsEnabled / hstsMaxAgeSeconds / hstsIncludeSubDomains init
    // params.
    supportsHsts: '8.5.0',
    // No OCSP-stapling element emitted by helpers/tomcat.js.
    supportsOcspStapling: false,
    // No PQ-aware code path; PQ key exchange depends on the JVM's TLS
    // implementation but Tomcat does not emit a hybrid-group token.
    supportsPq: false,
    tls13: '8.0.0',
    usesOpenssl: false,
  },
  traefik: {
    cipherFormat: 'go',
    latestVersion: '3.2.1',
    eolBefore: '2.11.0',
    name: 'Traefik',
    // Traefik 2.0.0 (Sep 2019) was the rewrite that introduced the
    // `tls.options` block (cipherSuites, curvePreferences, minVersion,
    // ...) the helper emits. Traefik 1.x had a different config language
    // with no equivalent per-suite / per-curve knob.
    supportsCipherSelection: '2.0.0',
    supportsCurveSelection: '2.0.0',
    // helpers/traefik.js:62-73 emits Traefik's HSTS Headers middleware
    // (stsSeconds + stsIncludeSubdomains); the Headers middleware shipped
    // with the 2.0 rewrite.
    supportsHsts: '2.0.0',
    // Traefik does not expose a per-cert OCSP-stapling toggle; OCSP
    // behavior is governed by Go's crypto/tls and the helper does not
    // emit a stapling directive.
    supportsOcspStapling: false,
    // Traefik 3.4.0 (Apr 2025) was the first stable release built with
    // Go >= 1.24 and therefore the first to negotiate X25519MLKEM768 via
    // its tls.curvePreferences directive.
    supportsPq: '3.4.0',
    tls13: '2.0.0',
    usesOpenssl: false,
  },
};
