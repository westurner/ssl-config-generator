import minver from './minver.js';

// GnuTLS priority-string template.
//
// GnuTLS configuration is expressed as a single priority string passed to
// gnutls_priority_init() (or set via the system "gnutls.config" file).
// GnuTLS 3.8.10 added the X25519-MLKEM768 hybrid post-quantum group; the
// SecP256r1MLKEM768 / SecP384r1MLKEM1024 codepoints are not yet exposed.
//
// References (see src/static/citations.bib):
//  - GnuTLS priority strings:     https://www.gnutls.org/manual/html_node/Priority-Strings.html
//  - GnuTLS 3.8.10 release notes: https://lists.gnupg.org/pipermail/gnutls-help/2025-March/thread.html
//  - draft-kwiatkowski-tls-ecdhe-mlkem
const PROTOCOL_MAP = {
  'TLSv1':   'VERS-TLS1.0',
  'TLSv1.1': 'VERS-TLS1.1',
  'TLSv1.2': 'VERS-TLS1.2',
  'TLSv1.3': 'VERS-TLS1.3',
};

// IANA TLS named groups -> GnuTLS GROUP-* tokens.
const GROUP_MAP = {
  'X25519MLKEM768':      'GROUP-X25519-MLKEM768',  // GnuTLS 3.8.10+
  'X25519':              'GROUP-X25519',
  'prime256v1':          'GROUP-SECP256R1',
  'secp384r1':           'GROUP-SECP384R1',
  'secp521r1':           'GROUP-SECP521R1',
  'ffdhe2048':           'GROUP-FFDHE2048',
  'ffdhe3072':           'GROUP-FFDHE3072',
  'ffdhe4096':           'GROUP-FFDHE4096',
};

export default (form, output) => {
  // Start from a blank slate ("NONE") and append directives so the priority
  // string is reproducible and deterministic regardless of GnuTLS defaults.
  const tokens = ['NONE', '+MAC-ALL', '+SIGN-ALL', '+COMP-NULL', '+CTYPE-X509'];

  // Protocol versions
  for (const p of output.protocols) {
    if (PROTOCOL_MAP[p]) tokens.push('+'+PROTOCOL_MAP[p]);
  }

  // Key-exchange groups (incl. PQ filtering already applied upstream).
  const groupTokens = [];
  for (const g of output.tlsCurves) {
    if (GROUP_MAP[g]) groupTokens.push('+'+GROUP_MAP[g]);
  }
  if (groupTokens.length === 0) {
    // Sane fallback so the priority string still parses.
    groupTokens.push('+GROUP-ALL');
  }
  tokens.push.apply(tokens, groupTokens);

  // TLS 1.3 cipher suites (AEAD-only) and TLS 1.2 ciphers, mapped from the
  // guideline. The mapping is intentionally coarse: GnuTLS aggregate tokens
  // such as +AES-128-GCM/+AES-256-GCM/+CHACHA20-POLY1305 cover the AEAD
  // suites used by the modern and intermediate Mozilla profiles.
  const cipherSuites = (output.cipherSuites || []).join(':');
  if (cipherSuites.includes('TLS_AES_128_GCM_SHA256') || (output.ciphers||[]).join(':').includes('AES128-GCM')) {
    tokens.push('+AES-128-GCM');
  }
  if (cipherSuites.includes('TLS_AES_256_GCM_SHA384') || (output.ciphers||[]).join(':').includes('AES256-GCM')) {
    tokens.push('+AES-256-GCM');
  }
  if (cipherSuites.includes('TLS_CHACHA20_POLY1305_SHA256') || (output.ciphers||[]).join(':').includes('CHACHA20-POLY1305')) {
    tokens.push('+CHACHA20-POLY1305');
  }
  if (form.config === 'old') {
    // GnuTLS legacy ciphers for "old" interop.
    tokens.push('+AES-128-CBC', '+AES-256-CBC', '+3DES-CBC', '+SHA1');
  }

  // Server cipher / group preference
  if (output.serverPreferredOrder) {
    tokens.push('%SERVER_PRECEDENCE');
  }

  const priority = tokens.join(':');

  let conf =
      '# '+output.header+'\n'+
      '# '+output.link+'\n'+
      '#\n'+
      '# GnuTLS priority string. Pass to gnutls_priority_init() or set\n'+
      '# system-wide via the [overrides] section of /etc/gnutls/config:\n'+
      '#     [priorities]\n'+
      '#     SYSTEM = '+priority+'\n'+
      '#\n'+
      '# Programs (e.g. wget, mutt, lftp) that honour the GnuTLS system\n'+
      '# config will then negotiate using these settings.\n';

  if (form.pq && form.pq !== 'none' && !minver('3.8.10', form.serverVersion)) {
    conf +=
      '#\n'+
      '# WARNING: GROUP-X25519-MLKEM768 requires GnuTLS 3.8.10 or newer.\n'+
      '#          Older GnuTLS releases do not implement ML-KEM.\n';
  }

  conf += '\n'+priority+'\n';

  return conf;
};
