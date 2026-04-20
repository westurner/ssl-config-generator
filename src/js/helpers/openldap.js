import minver from './minver.js';

// OpenLDAP (slapd) TLS configuration template.
//
// OpenLDAP delegates all TLS primitives to its linked TLS backend (OpenSSL
// or GnuTLS). The directives below configure slapd.conf-style syntax; the
// equivalent cn=config attributes (`olcTLSCipherSuite`, `olcTLSProtocolMin`,
// `olcTLSECName`, ...) accept the same values and are noted in comments.
//
// Directives used:
//   - TLSCertificateFile / TLSCertificateKeyFile / TLSCACertificateFile
//   - TLSCipherSuite        (OpenSSL cipher string for TLSv1.2 and earlier)
//   - TLSProtocolMin        (OpenLDAP version-numbering: 3.1=TLS 1.0,
//                            3.2=TLS 1.1, 3.3=TLS 1.2, 3.4=TLS 1.3)
//   - TLSECName             (colon-separated curve / group list, OpenLDAP
//                            2.5+ — earlier versions accept a single name
//                            only)
//   - TLSDHParamFile        (only when usesDhe; FFDHE PEM)
//
// Notes on TLSv1.3 + post-quantum:
//   - OpenLDAP exposes NO directive for TLSv1.3 ciphersuites; those are
//     inherited from the system openssl.cnf [system_default_sect]
//     Ciphersuites line. Use the "OpenSSL config (openssl.cnf)" target in
//     this tool to set them system-wide.
//   - ML-KEM hybrid key-exchange groups (X25519MLKEM768,
//     SecP256r1MLKEM768, SecP384r1MLKEM1024) are TLS 1.3-only (RFC-track
//     `key_share` extension) and require OpenSSL >= 3.5.0. They are passed
//     through TLSECName as ordinary curve names; older OpenSSL would
//     silently ignore unknown names.
//
// References (see src/static/citations.bib):
//   - slapd-config(5):              https://www.openldap.org/doc/admin26/slapdconf2.html
//   - slapd.conf(5):                https://www.openldap.org/doc/admin26/guide.html
//   - draft-kwiatkowski-tls-ecdhe-mlkem
//   - NIST FIPS 203 (ML-KEM)
export default (form, output) => {
  const groupsLine = output.tlsCurves.join(':');
  const ciphersLine = (output.ciphers || []).filter(c => c !== '@SECLEVEL=0').join(':');
  const protocols = output.protocols || [];

  // OpenLDAP's TLSProtocolMin uses the on-the-wire SSL/TLS major.minor
  // version numbering (3.0=SSL3, 3.1=TLS1.0, 3.2=TLS1.1, 3.3=TLS1.2,
  // 3.4=TLS1.3). state.js emits the legacy floor as 'TLSv1' (not
  // 'TLSv1.0'); both spellings map to 3.1.
  const tlsProtocolMin = (p) => {
    if (p === 'TLSv1.3')                       return '3.4';
    if (p === 'TLSv1.2')                       return '3.3';
    if (p === 'TLSv1.1')                       return '3.2';
    if (p === 'TLSv1' || p === 'TLSv1.0')      return '3.1';
    return '3.3'; // TLS 1.2 fallback
  };
  const minProtocol = tlsProtocolMin(protocols[0] || 'TLSv1.2');
  const minProtocolLabel = protocols[0] || 'TLSv1.2';

  let conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      '#\n'+
      '# OpenLDAP (slapd) TLS configuration ('+form.config+' profile).\n'+
      '#\n'+
      '# slapd.conf-style directives are shown below; the equivalent\n'+
      '# cn=config attributes (olcTLSCipherSuite, olcTLSProtocolMin,\n'+
      '# olcTLSECName, ...) accept the same values. TLSv1.3 ciphersuites\n'+
      '# are NOT settable via slapd directives; they are inherited from\n'+
      '# the system openssl.cnf [system_default_sect] Ciphersuites line\n'+
      '# (see the "OpenSSL config (openssl.cnf)" target in this tool).\n';

  if (form.pq && form.pq !== 'none') {
    conf +=
      '#\n'+
      '# Post-quantum: ML-KEM hybrid key-exchange groups (X25519MLKEM768,\n'+
      '# SecP256r1MLKEM768, SecP384r1MLKEM1024) are TLS 1.3-only\n'+
      '# (key_share extension) and are passed to OpenSSL via TLSECName.\n';
    if (!minver("3.5.0", form.opensslVersion)) {
      conf +=
      '#\n'+
      '# WARNING: built-in ML-KEM hybrid groups require OpenSSL 3.5.0 or\n'+
      '#          newer. Earlier versions need the "oqs-provider" from\n'+
      '#          liboqs (loaded via openssl.cnf) or OpenLDAP will\n'+
      '#          silently skip the unrecognized group names.\n';
    }
    if (form.pq === 'only') {
      conf +=
      '#\n'+
      '# PQ-only mode: TLSProtocolMin is pinned to 3.4 (TLS 1.3) below;\n'+
      '# ML-KEM groups are not defined for TLS 1.2 and earlier, so\n'+
      '# allowing a lower MinProtocol would mean a TLS-1.2 fallback would\n'+
      '# silently negotiate classical-only key exchange.\n';
    }
  }

  conf +=
      '\n'+
      'TLSCertificateFile    /path/to/signed_cert_plus_intermediates\n'+
      'TLSCertificateKeyFile /path/to/private_key\n'+
      'TLSCACertificateFile  /path/to/ca_certs\n'+
      '\n'+
      '# Minimum protocol version. OpenLDAP uses on-the-wire numbering:\n'+
      '#   3.1 = TLS 1.0, 3.2 = TLS 1.1, 3.3 = TLS 1.2, 3.4 = TLS 1.3.\n'+
      'TLSProtocolMin '+minProtocol+'   # '+minProtocolLabel+'\n';

  if (ciphersLine.length) {
    conf +=
      '\n'+
      '# TLSv1.2 (and earlier) cipher list (OpenSSL cipher syntax).\n'+
      '# TLSv1.3 ciphersuites are not configurable here — see openssl.cnf.\n'+
      'TLSCipherSuite '+ciphersLine+'\n';
  }

  if (groupsLine.length) {
    conf +=
      '\n'+
      '# Key-exchange groups (a.k.a. "curves") in preference order.\n'+
      '# OpenLDAP 2.5+ accepts a colon-separated list; earlier releases\n'+
      '# only honour the first entry.\n';
    if (form.pq === 'only') {
      conf +=
      '# PQ-only mode: classical curves are intentionally omitted.\n';
    }
    else if (form.pq === 'hybrid') {
      conf +=
      '# Hybrid PQ mode: ML-KEM hybrid groups are listed first, with\n'+
      '# classical curves retained for interoperability with peers that\n'+
      '# do not yet implement post-quantum key exchange.\n';
    }
    conf +=
      'TLSECName '+groupsLine+'\n';
  }

  if (output.usesDhe) {
    conf +=
      '\n'+
      '# '+output.dhCommand+' > /path/to/dhparam\n'+
      'TLSDHParamFile /path/to/dhparam\n';
  }

  return conf;
};
