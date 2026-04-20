// configs for the supported pieces of software
// hasVersions, showSupports, supportsHsts, and usesOpenssl only need to be defined if false
// supportsPq is assumed FALSE unless explicitly set (opposite default of
// the *Selection flags below): a helper opts IN by declaring it has a PQ-aware
// render branch today (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024
// codepoints, or a managed-policy alias like s2n-tls 'default_pq' that
// negotiates ML-KEM hybrids automatically). Helpers that have NO PQ surface
// whatsoever (no group token, no comment, no policy alias) leave the flag
// unset. The capability matrix surfaced by this flag answers the operator
// question "is this server even ABLE to negotiate post-quantum key exchange
// today?" — orthogonal to the per-curve / per-cipher mitigation-latency
// flags below.
//   - supportsPq:'<ver>' → helper has a PQ-aware codepath in src/js/helpers/;
//                          the value is the first upstream release that
//                          surfaced PQ key exchange (mirrors how `tls13` and
//                          version-string `supportsOcspStapling` are
//                          encoded). State.js coerces this to a boolean on
//                          output.supportsPq so the UI / harness can branch
//                          on it the same way they branch on
//                          supportsCurveSelection.
//   - supportsPq:true    → also accepted (treated as "supports PQ, version
//                          unknown / not yet recorded").
//   - (omitted)          → no PQ surface; the helper ignores form.pq.
//
// supportsCipherSelection, supportsCurveSelection, and supportsHsts are
// assumed `true` unless defined otherwise. Each accepts the same value
// shapes as `supportsPq` / `supportsOcspStapling`:
//   - '<ver>'  → the first upstream release that surfaced the feature (the
//                value is documentation-only — state.js coerces these three
//                flags to a boolean via `!== false` so the version string
//                does NOT cause runtime gating; `eolBefore` is the floor
//                that decides which historical versions are even
//                selectable in the UI). Mirrors how `supportsPq` and
//                version-string `supportsOcspStapling` are encoded.
//   - true     → "supported, version unknown / not yet recorded".
//   - (omit)   → same as true.
//   - false    → not supported by this helper at all.
//   - supportsCipherSelection:false  → the helper cannot emit a per-cipher list
//                                      (e.g. AWS ALB / s2n-tls expose only named
//                                      "policy" identifiers).
//   - supportsCurveSelection:false   → the helper cannot express a TLS named-group
//                                      / curve preference (e.g. MySQL, Tomcat,
//                                      Jetty, Redis, Squid, AWS ELB/ALB, s2n-tls,
//                                      rustls, the LiteSpeed family, Coturn,
//                                      OracleHTTP).
//   - supportsHsts:false             → not an HTTP server (Postfix, Dovecot,
//                                      OpenLDAP, Coturn, MySQL, …).
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
    tls13: '2.4.36',
  },
  awsalb: {
    hasVersions: false,
    latestVersion: '2023.3.22',
    name: 'AWS ALB',
    showSupports: false,
    supportsCipherSelection: false,
    supportsCurveSelection: false,
    supportsOcspStapling: false,
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
    supportsCurveSelection: false,
    supportsHsts: false,
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
    supportsCurveSelection: false,
    supportsHsts: false,
    tls13: '4.6.2',
  },
  dovecot: {
    latestVersion: '2.4.2',
    eolBefore: '2.2.36', // https://dovecot.org/list/dovecot/2018-August/112536.html
    name: 'Dovecot',
    showSupports: false,
    supportsHsts: false,
    // ssl_curve_list (renamed to ssl_curves in 2.4) was added in Dovecot
    // 2.2.6 (Jul 2014). Earlier 2.2.x had no per-curve knob and used
    // OpenSSL's compiled-in default group preference.
    supportsCurveSelection: '2.2.6',
    tls13: '2.3.15',
  },
  exim: {
    latestVersion: '4.98',
    eolBefore: '4.98',
    name: 'Exim',
    showSupports: false,
    supportsHsts: false,
    // tls_eccurve was added in Exim 4.80 (May 2012) for the GnuTLS build
    // and extended to OpenSSL builds with the helper-noted gate of
    // 4.97 + OpenSSL 1.1.1 (helpers/exim.js:17). The capability statement
    // is "first upstream release that surfaced the directive".
    supportsCurveSelection: '4.80',
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
    supportsHsts: false,
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
    supportsCurveSelection: false,
    supportsHsts: false,
    tls13: '9.4.12',
    usesOpenssl: false,
  },
  lighttpd: {
    latestVersion: '1.4.82',
    eolBefore: '1.4.69',
    name: 'lighttpd',
    supportsOcspStapling: '1.4.56',
    tls13: '1.4.48',
  },
  litespeed: {
    latestVersion: '6.3.5',
    eolBefore: '5.4.12',
    name: 'LiteSpeed',
    supportsCurveSelection: false,
    supportsOcspStapling: '1.2',
    tls13: '5.4.12',
  },
  mysql: {
    latestVersion: '9.1.0',
    eolBefore: '8.0.0',
    name: 'MySQL',
    showSupports: false,
    supportsCurveSelection: false,
    supportsHsts: false,
    tls13: '8.0.16',
  },
  nginx: {
    latestVersion: '1.27.3',
    eolBefore: '1.26.0',
    name: 'nginx',
    // The `always` parameter on `add_header` (used by the helper to emit
    // HSTS so the header is set on error responses too) was added in
    // nginx 1.7.5; see helpers/nginx.js:33. Earlier nginx supported
    // `add_header` since 0.5.x but only on 2xx/3xx responses, which is
    // unsafe for HSTS (RFC 6797 §7.2 requires the header on every
    // response over a secure transport).
    supportsHsts: '1.7.5',
    supportsOcspStapling: '1.3.7',
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
    supportsHsts: false,
    // The `Groups` SSL_CONF command (the openssl.cnf form of
    // `-groups`/`SSL_CONF_cmd("Groups", ...)`) was added in OpenSSL 1.1.1
    // when the named-group preference list replaced the older
    // `Curves` command for TLS 1.3.
    supportsCurveSelection: '1.1.1',
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
    supportsCurveSelection: false,
    supportsOcspStapling: '1.2',
    tls13: '1.4.35',
  },
  openldap: {
    latestVersion: '2.6.9',
    eolBefore: '2.6.0',
    name: 'OpenLDAP (slapd)',
    showSupports: false,
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
    supportsCurveSelection: false,
    // Oracle HTTP Server 12.2.1 (12cR2, Oct 2015) was the first release
    // to ship `SSLOCSPEnable` and the related Oracle-mod_ossl OCSP
    // stapling directives; see helpers/oraclehttp.js:36
    // (`minver("12.2.1", form.serverVersion)`).
    supportsOcspStapling: '12.2.1',
    usesOpenssl: false,
  },
  postfix: {
    latestVersion: '3.9.0',
    eolBefore: '3.6.0',
    name: 'Postfix',
    showSupports: false,
    supportsHsts: false,
    // tls_eecdh_auto_curves was added in Postfix 3.4.0 (Feb 2019); see
    // helpers/postfix.js:14 (`minver("3.4.0", form.serverVersion)`).
    // Earlier Postfix could only set a single named curve via
    // smtpd_tls_eecdh_grade + tls_eecdh_strong_curve / _ultra_curve.
    supportsCurveSelection: '3.4.0',
    tls13: '3.3.2',
  },
  postgresql: {
    latestVersion: '17.2',
    eolBefore: '13.0',
    name: 'PostgreSQL',
    showSupports: false,
    supportsHsts: false,
    // ssl_groups (the per-server TLS named-group preference list) was
    // added in PostgreSQL 18.0; see helpers/postgresql.js:18
    // (`minver("18.0.0", form.serverVersion)`). PostgreSQL 13–17 had only
    // ssl_ecdh_curve (single curve, ECDHE-only) — captured implicitly by
    // the helper's fallback emit; the capability flag here documents the
    // first release with a true preference-list directive.
    supportsCurveSelection: '18.0.0',
    tls13: '12.0',
  },
  proftpd: {
    latestVersion: '1.3.8',
    eolBefore: '1.3.8',  // http://www.proftpd.org/docs/howto/Versioning.html
    name: 'ProFTPD',
    showSupports: false,
    supportsHsts: false,
    supportsOcspStapling: '1.3.6',
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
    supportsCurveSelection: false,
    supportsHsts: false,
    // Redis 6.0.0 (Apr 2020) was the first release with built-in TLS
    // support and the `tls-ciphers` / `tls-ciphersuites` config
    // directives; see helpers/redis.js:40 (`!minver("6.0", ...)` bail
    // out — the entire TLS config is gated on Redis 6+).
    supportsCipherSelection: '6.0.0',
    tls13: '6.0',
  },
  rust: {
    cipherFormat: 'iana',
    latestVersion: '0.23.18',
    eolBefore: '0.23.0',
    name: 'Rust (rustls)',
    showSupports: false,
    supportsCurveSelection: false,
    supportsHsts: false,
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
    supportsCurveSelection: false,
    supportsHsts: false,
    tls13: '4',
  },
  stunnel: {
    latestVersion: '5.73',
    name: 'stunnel',
    supportsHsts: false,
    tls13: '5.50',
  },
  tomcat: {
    latestVersion: '11.0.1',
    eolBefore: '9.0.0',
    name: 'Tomcat',
    supportsCurveSelection: false,
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
    // Traefik 3.4.0 (Apr 2025) was the first stable release built with
    // Go >= 1.24 and therefore the first to negotiate X25519MLKEM768 via
    // its tls.curvePreferences directive.
    supportsPq: '3.4.0',
    tls13: '2.0.0',
    usesOpenssl: false,
  },
};
