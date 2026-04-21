import minver from './minver.js';

// Generate an openssl.cnf snippet that configures system-wide TLS defaults
// for OpenSSL-based applications. This is consumed by every program that
// uses libssl/libcrypto via the default config loader, including Python's
// `ssl` module (CPython calls `OPENSSL_init_ssl` / loads the system
// openssl.cnf), curl, libpq, and many others.
//
// Locating / overriding the file at runtime
// -----------------------------------------
// The default location is reported by `openssl version -d` (typically
// /etc/ssl/openssl.cnf on Linux, /usr/local/etc/openssl@3/openssl.cnf
// on macOS Homebrew). To use a DIFFERENT openssl.cnf for a specific
// process — e.g. to apply this snippet to one server binary without
// touching the system-wide file — set the OPENSSL_CONF environment
// variable before launching the process:
//
//     OPENSSL_CONF=/path/to/your-openssl.cnf <binary> ...
//
// libssl has honoured OPENSSL_CONF since OpenSSL 0.9.7; see
// openssl-config(5) and OPENSSL_init_crypto(3). This is the same
// override referenced by helpers tagged pqViaOpensslCnf:true in
// configs.js (coturn, litespeed, mysql, openlitespeed, redis, squid):
// those servers have no native group / curve directive, so OPENSSL_CONF
// is the per-process knob for enabling ML-KEM hybrid key exchange
// without modifying /etc/ssl/openssl.cnf system-wide.
//
// References (see src/static/citations.bib):
//  - openssl-config(5):           https://docs.openssl.org/3.5/man5/config/
//  - SSL_CONF_cmd(3):             https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/
//  - OpenSSL 3.5 release notes:   https://github.com/openssl/openssl/blob/openssl-3.5/NEWS.md
//  - draft-kwiatkowski-tls-ecdhe-mlkem (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 codepoints)
//  - NIST FIPS 203 (ML-KEM)
//  - Python ssl module:           https://docs.python.org/3/library/ssl.html
export default (form, output) => {
  const groupsLine = output.tlsCurves.join(':');
  const ciphersuitesLine = (output.cipherSuites || []).join(':');
  const ciphersLine = (output.ciphers || []).filter(c => c !== '@SECLEVEL=0').join(':');
  const minProtocol = output.protocols[0] || 'TLSv1.2';
  const maxProtocol = output.protocols[output.protocols.length - 1] || 'TLSv1.3';

  let conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      '#\n'+
      '# This is a snippet for OpenSSL\'s configuration file (openssl.cnf).\n'+
      '# It applies system-wide to programs that use OpenSSL via the\n'+
      '# default config loader, including Python\'s ssl module, curl,\n'+
      '# libpq, Rust apps that link the `openssl` crate, and many others.\n'+
      '# (Pure-Rust apps that use rustls do NOT honour openssl.cnf; see\n'+
      '# the "Rust (rustls)" target instead. For Python applications that\n'+
      '# prefer to configure TLS in code, see the "Python (ssl module)"\n'+
      '# target which emits an ssl.SSLContext directly.)\n'+
      '#\n'+
      '# MinProtocol / MaxProtocol below mirror the chosen Mozilla profile:\n'+
      '#   - "modern"        -> MinProtocol = TLSv1.3\n'+
      '#   - "intermediate"  -> MinProtocol = TLSv1.2 (TLS 1.2 is still\n'+
      '#                        required by intermediate for legacy clients;\n'+
      '#                        select the "modern" profile to require 1.3)\n'+
      '#   - "old"           -> MinProtocol = TLSv1   (last-resort interop)\n'+
      '# When PQ-only mode is selected, MinProtocol is always TLSv1.3:\n'+
      '# ML-KEM key-exchange groups are only defined for TLS 1.3.\n'+
      '#\n'+
      '# Locate your active openssl.cnf with:\n'+
      '#     openssl version -d\n'+
      '# (the file is named "openssl.cnf" in that directory). To use a\n'+
      '# different openssl.cnf for one process only — e.g. to apply this\n'+
      '# snippet to a single server binary without editing the system-wide\n'+
      '# file — set the OPENSSL_CONF environment variable before launching\n'+
      '# the process:\n'+
      '#     OPENSSL_CONF=/path/to/your-openssl.cnf <binary> ...\n'+
      '# libssl has honoured OPENSSL_CONF since OpenSSL 0.9.7 (see\n'+
      '# openssl-config(5) and OPENSSL_init_crypto(3)). This is the\n'+
      '# per-process knob referenced by other targets in this generator\n'+
      '# (Coturn, MySQL, Redis, Squid, LiteSpeed, OpenLiteSpeed) that\n'+
      '# have no native group / curve directive.\n'+
      '#\n'+
      '# To inspect available providers / KEMs / groups:\n'+
      '#     openssl version\n'+
      '#     openssl list -providers\n'+
      '#     openssl list -kem-algorithms\n'+
      '#     openssl list -key-exchange-algorithms\n';

  if (form.pq && form.pq !== 'none' && !minver("3.5.0", form.opensslVersion)) {
    conf +=
      '#\n'+
      '# WARNING: built-in ML-KEM hybrid groups (X25519MLKEM768,\n'+
      '#          SecP256r1MLKEM768, SecP384r1MLKEM1024) require\n'+
      '#          OpenSSL 3.5.0 or newer. Earlier versions need the\n'+
      '#          "oqs-provider" from liboqs to expose these groups.\n';
  }

  conf +=
      '\n'+
      'openssl_conf = openssl_init\n'+
      '\n'+
      '[openssl_init]\n'+
      'ssl_conf = ssl_module\n'+
      '\n'+
      '[ssl_module]\n'+
      '# Apply the configuration to every SSL_CTX created by libssl.\n'+
      'system_default = system_default_sect\n'+
      '\n'+
      '[system_default_sect]\n'+
      'MinProtocol = '+minProtocol+'\n'+
      'MaxProtocol = '+maxProtocol+'\n';

  if (ciphersLine.length) {
    conf +=
      '# TLSv1.2 (and earlier) cipher list (OpenSSL syntax)\n'+
      'CipherString = '+ciphersLine+'\n';
  }
  if (ciphersuitesLine.length) {
    conf +=
      '# TLSv1.3 cipher suites (IANA names, colon-separated)\n'+
      'Ciphersuites = '+ciphersuitesLine+'\n';
  }

  if (groupsLine.length) {
    conf +=
      '# Key-exchange groups (a.k.a. "curves") in preference order.\n';
    if (form.pq === 'only') {
      conf +=
      '# PQ-only mode: classical curves are intentionally omitted.\n';
    }
    else if (form.pq === 'hybrid') {
      conf +=
      '# Hybrid PQ mode: ML-KEM hybrid groups are listed first, with\n'+
      '# classical curves retained for interoperability with peers that\n'+
      '# do not yet implement post-quantum key exchange. Note that a MITM\n'+
      '# capable of stripping the hybrid group from ClientHello can still\n'+
      '# downgrade the connection to a classical group; PQ-only mode\n'+
      '# eliminates that risk at the cost of interoperability.\n';
    }
    conf +=
      'Groups = '+groupsLine+'\n';
  }

  if (output.serverPreferredOrder) {
    conf +=
      '# Honor server cipher / group preference (SSL_CONF \'Options\' directive).\n'+
      'Options = ServerPreference\n';
  }

  return conf;
};
