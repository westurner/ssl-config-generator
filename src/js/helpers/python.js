import minver from './minver.js';

// Python `ssl` module configuration template.
//
// Python's `ssl` module is a thin wrapper around OpenSSL. Many TLS
// defaults — including TLSv1.3 ciphersuites and group preferences on
// older interpreters — are inherited from the system `openssl.cnf`.
// The "OpenSSL config (openssl.cnf)" target in this tool can be used
// to influence those defaults system-wide; this template configures the
// SSLContext directly via the Python API for application-local control.
//
// API surface used:
//   - ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)            (Python 3.6+)
//   - SSLContext.minimum_version / .maximum_version       (3.7+)
//   - SSLContext.set_ciphers(string)                      (TLSv1.2 and earlier
//                                                          ciphers, OpenSSL syntax)
//   - SSLContext.set_ecdh_curve(name)                     (single curve, 3.3+)
//   - SSLContext.set_groups(groups)                       (3.13+, multi-group
//                                                          preference list)
//
// References (see src/static/citations.bib):
//  - Python ssl module:           https://docs.python.org/3/library/ssl.html
//  - PEP 644 (Require OpenSSL 1.1.1 or newer):
//                                 https://peps.python.org/pep-0644/
//  - draft-kwiatkowski-tls-ecdhe-mlkem (X25519MLKEM768 codepoint)
//  - NIST FIPS 203 (ML-KEM)
export default (form, output) => {
  const groupsLine = output.tlsCurves.join(':');
  const ciphersLine = (output.ciphers || []).filter(c => c !== '@SECLEVEL=0').join(':');
  const protocols = output.protocols || [];
  const supportsTls13 = protocols.includes('TLSv1.3');
  // Map Mozilla protocol tokens to ssl.TLSVersion.* members.
  const tlsVersionEnum = (p) => {
    if (p === 'TLSv1.3') return 'TLSv1_3';
    if (p === 'TLSv1.2') return 'TLSv1_2';
    if (p === 'TLSv1.1') return 'TLSv1_1';
    if (p === 'TLSv1' || p === 'TLSv1.0') return 'TLSv1';
    return 'TLSv1_2';
  };
  // ML-KEM hybrid key-exchange groups (X25519MLKEM768, SecP256r1MLKEM768,
  // SecP384r1MLKEM1024) are defined exclusively for TLS 1.3 (key_share
  // extension); they cannot be negotiated on a TLS 1.2 connection. So:
  //   - pq=='only'   → defensively pin minimum_version=TLSv1_3 in python.js
  //                    itself (don't rely on state.js's protocol override
  //                    upstream — defense in depth).
  //   - pq=='hybrid' → leave the floor at protocols[0]; on a TLS 1.2
  //                    fallback the connection is classical-only, which is
  //                    the documented hybrid trade-off.
  //   - pq=='none'   → no PQ groups advertised regardless of protocol.
  const minProtocol = form.pq === 'only'
    ? 'TLSv1_3'
    : tlsVersionEnum(protocols[0] || 'TLSv1.2');
  const maxProtocol = tlsVersionEnum(protocols[protocols.length - 1] || 'TLSv1.3');
  // Pick the first non-PQ curve as the single-curve fallback for
  // SSLContext.set_ecdh_curve() on Python < 3.13. ML-KEM hybrid groups
  // are not accepted by set_ecdh_curve(), so skip them in the fallback.
  const fallbackCurve =
    output.tlsCurves.find(c => !/MLKEM/i.test(c)) || 'prime256v1';

  let conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      '#\n'+
      '# Python `ssl` module configuration ('+form.config+' profile).\n'+
      '#\n'+
      '# The Python `ssl` module is a thin wrapper around OpenSSL. The\n'+
      '# protocol-version floor, TLSv1.2 cipher list, and (on Python 3.13+)\n'+
      '# group / curve preferences are pinned below via the SSLContext API.\n'+
      '# TLSv1.3 ciphersuites are NOT exposed by Python; they are inherited\n'+
      '# from the system `openssl.cnf` `[system_default_sect]` Ciphersuites\n'+
      '# directive — use the "OpenSSL config (openssl.cnf)" target in this\n'+
      '# tool to set them system-wide.\n'+
      '#\n'+
      '# Requires:\n'+
      '#   - Python >= 3.10 (modern SSLContext API; older 3.x works with\n'+
      '#                     adjustments).\n';
  if (supportsTls13) {
    conf +=
      '#   - Python >= 3.13 for SSLContext.set_groups(); earlier versions\n'+
      '#                     can pin a single curve via set_ecdh_curve()\n'+
      '#                     (see fallback below) or rely on openssl.cnf.\n';
  }
  if (form.pq && form.pq !== 'none') {
    conf +=
      '#   - OpenSSL >= 3.5 for built-in ML-KEM hybrid groups\n'+
      '#                     (X25519MLKEM768, SecP256r1MLKEM768,\n'+
      '#                     SecP384r1MLKEM1024). Inspect with:\n'+
      '#                         python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"\n';
    if (!minver("3.5.0", form.opensslVersion)) {
      conf +=
      '#\n'+
      '# WARNING: built-in ML-KEM hybrid groups require OpenSSL 3.5.0 or\n'+
      '#          newer. Earlier versions need the "oqs-provider" from\n'+
      '#          liboqs to expose these groups (loaded via openssl.cnf).\n';
    }
  }
  conf +=
      '\n'+
      'import ssl\n'+
      '\n'+
      'context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n'+
      'context.minimum_version = ssl.TLSVersion.'+minProtocol+'\n'+
      'context.maximum_version = ssl.TLSVersion.'+maxProtocol+'\n'+
      '\n'+
      'context.load_cert_chain(\n'+
      '    certfile="/path/to/signed_cert_plus_intermediates",\n'+
      '    keyfile="/path/to/private_key",\n'+
      ')\n';

  if (ciphersLine.length) {
    conf +=
      '\n'+
      '# TLSv1.2 (and earlier) cipher list (OpenSSL syntax).\n'+
      'context.set_ciphers("'+ciphersLine+'")\n';
  }

  if (groupsLine.length) {
    conf +=
      '\n'+
      '# Key-exchange groups (a.k.a. "curves") in preference order.\n'+
      '# ML-KEM hybrid groups (X25519MLKEM768, SecP256r1MLKEM768,\n'+
      '# SecP384r1MLKEM1024) are TLS 1.3-only (key_share extension); a\n'+
      '# TLS 1.2 connection silently advertises none of them.\n';
    if (form.pq === 'only') {
      conf +=
      '# PQ-only mode: classical curves are intentionally omitted, and\n'+
      '# minimum_version is pinned to TLSv1_3 above to prevent a silent\n'+
      '# TLS 1.2 fallback from negotiating classical-only key exchange.\n';
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
      'try:\n'+
      '    # Python 3.13+: full multi-group preference list.\n'+
      '    context.set_groups("'+groupsLine+'")\n'+
      'except AttributeError:\n';
    if (form.pq === 'only') {
      // PQ-only mode on Python < 3.13 has NO safe single-curve fallback:
      // set_ecdh_curve() rejects ML-KEM hybrid names, so silently calling
      // it with a classical curve would defeat the user's PQ-only choice.
      // Raise loudly instead.
      conf +=
      '    # Python < 3.13 cannot express a multi-group preference list,\n'+
      '    # and set_ecdh_curve() rejects ML-KEM hybrid names. Silently\n'+
      '    # falling back to a classical single curve here would defeat\n'+
      '    # PQ-only mode, so raise loudly. Upgrade Python to 3.13+, or\n'+
      '    # configure groups system-wide via openssl.cnf [system_default_sect]\n'+
      '    # Groups (see the "OpenSSL config (openssl.cnf)" target).\n'+
      '    raise RuntimeError(\n'+
      '        "PQ-only mode requires Python >= 3.13 (SSLContext.set_groups); "\n'+
      '        "set_ecdh_curve() cannot express ML-KEM hybrid groups. "\n'+
      '        "Configure groups via openssl.cnf instead."\n'+
      '    )\n';
    }
    else {
      conf +=
      '    # Python < 3.13: only a single curve can be pinned via the API.\n'+
      '    # For a full PQ-aware group list on older interpreters, configure\n'+
      '    # the system openssl.cnf [system_default_sect] Groups directive.\n'+
      '    context.set_ecdh_curve("'+fallbackCurve+'")\n';
    }
  }

  if (output.serverPreferredOrder) {
    conf +=
      '\n'+
      '# Honor server cipher preference (mirrors the OpenSSL\n'+
      '# SSL_OP_CIPHER_SERVER_PREFERENCE option).\n'+
      'context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE\n';
  }

  conf +=
      '\n'+
      '# Wrap a TCP socket and serve. The `ssl` module itself does not\n'+
      '# emit HTTP headers; HSTS must be set by the HTTP layer above.\n'+
      'import socket\n'+
      'with socket.create_server(("0.0.0.0", 443)) as sock:\n'+
      '    with context.wrap_socket(sock, server_side=True) as ssock:\n'+
      '        # Accept connections, dispatch to your handler, etc.\n'+
      '        pass\n';

  if (form.hsts) {
    conf +=
      '\n'+
      '# HSTS: when wrapping this SSLContext in an HTTP framework\n'+
      '# (http.server, Flask, Django, FastAPI, aiohttp, ...), emit the\n'+
      '# following response header on every TLS response:\n'+
      '#     Strict-Transport-Security: max-age='+output.hstsMaxAge+'; includeSubDomains\n';
  }

  return conf;
};
