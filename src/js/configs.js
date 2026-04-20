// configs for the supported pieces of software
// hasVersions, showSupports, supportsHsts, and usesOpenssl only need to be defined if false
// supportsPq is assumed FALSE unless explicitly set to true (opposite default of
// the *Selection flags below): a helper opts IN by declaring it has a PQ-aware
// render branch today (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024
// codepoints, or a managed-policy alias like s2n-tls 'default_pq' that
// negotiates ML-KEM hybrids automatically). Helpers that have NO PQ surface
// whatsoever (no group token, no comment, no policy alias) leave the flag
// unset. The capability matrix surfaced by this flag answers the operator
// question "is this server even ABLE to negotiate post-quantum key exchange
// today?" — orthogonal to the per-curve / per-cipher mitigation-latency
// flags below.
//   - supportsPq:true  → helper has a PQ-aware codepath in src/js/helpers/.
//                        State.js mirrors this onto output.supportsPq so the
//                        UI / harness can branch on it the same way they
//                        branch on supportsCurveSelection.
//   - (omitted)        → no PQ surface; the helper ignores form.pq.
//
// supportsCipherSelection and supportsCurveSelection are assumed `true` unless defined otherwise.
//   - supportsCipherSelection:false  → the helper cannot emit a per-cipher list
//                                      (e.g. AWS ALB / s2n-tls expose only named
//                                      "policy" identifiers).
//   - supportsCurveSelection:false   → the helper cannot express a TLS named-group
//                                      / curve preference (e.g. MySQL, Tomcat,
//                                      Jetty, Redis, Squid, AWS ELB/ALB, s2n-tls,
//                                      rustls, the LiteSpeed family, Coturn,
//                                      OracleHTTP).
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
    supportsPq: true,
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
    tls13: '2.3.15',
  },
  exim: {
    latestVersion: '4.98',
    eolBefore: '4.98',
    name: 'Exim',
    showSupports: false,
    supportsHsts: false,
    tls13: '4.92.0',
  },
  go: {
    cipherFormat: 'go',
    latestVersion: '1.23.3',
    eolBefore: '1.22.0',
    name: 'Go',
    supportsPq: true,
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
    supportsPq: true,
    tls13: '3.6.4',
    usesOpenssl: false,
    // GnuTLS 3.8.10 added the X25519-MLKEM768 hybrid PQ group.
  },
  haproxy: {
    latestVersion: '3.0',
    eolBefore: '2.2',
    name: 'HAProxy',
    tls13: '1.8.0',
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
    supportsOcspStapling: '1.3.7',
    tls13: '1.13.0',
  },
  openssl: {
    latestVersion: '4.0.0',
    eolBefore: '3.0.0',
    tls13: '1.1.1',
  },
  opensslcnf: {
    latestVersion: '3.6.1',
    eolBefore: '3.0.0',
    name: 'OpenSSL config (openssl.cnf)',
    showSupports: false,
    supportsHsts: false,
    supportsPq: true,
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
  oraclehttp: {
    cipherFormat: 'iana',
    latestVersion: '12.2.1',
    name: 'Oracle HTTP',
    supportsCurveSelection: false,
    usesOpenssl: false,
  },
  postfix: {
    latestVersion: '3.9.0',
    eolBefore: '3.6.0',
    name: 'Postfix',
    showSupports: false,
    supportsHsts: false,
    tls13: '3.3.2',
  },
  postgresql: {
    latestVersion: '17.2',
    eolBefore: '13.0',
    name: 'PostgreSQL',
    showSupports: false,
    supportsHsts: false,
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
    supportsPq: true,
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
    supportsPq: true,
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
    supportsPq: true,
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
    supportsPq: true,
    tls13: '2.0.0',
    usesOpenssl: false,
  },
};
