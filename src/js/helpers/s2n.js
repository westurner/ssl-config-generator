import minver from './minver.js';
import { safe } from './ctx.js';

// s2n-tls (https://github.com/aws/s2n-tls) C library template.
//
// s2n-tls is a C TLS library from AWS, not a standalone server. This
// template emits a minimal C snippet that constructs an s2n_config and
// is meant to be embedded inside the user's application.
//
// s2n-tls is configured almost entirely via *named security policies*
// passed to s2n_config_set_cipher_preferences(). Each policy bundles a
// protocol-version floor, a ciphersuite list, signature schemes, and
// (for the PQ-capable policies) KEM groups. Users do not normally
// hand-pick OpenSSL-style cipher strings, so this template does not try
// to render output.ciphers / output.cipherSuites; instead it maps each
// Mozilla profile (modern / intermediate / old) onto the closest stock
// s2n policy and documents the choice in the header comment.
//
// References (see src/static/citations.bib):
//  - s2n-tls README:                 https://github.com/aws/s2n-tls
//  - s2n-tls security policies:      https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch06-security-policies.md
//  - s2n-tls PQ ("default_pq"):      https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch15-post-quantum.md
//  - draft-kwiatkowski-tls-ecdhe-mlkem

// Mozilla profile -> stock s2n named security policy.
//
// "default_tls13" (currently aliased to fixed policy 20240503) negotiates
// TLS 1.2 and TLS 1.3 with AES-GCM / ChaCha20-Poly1305 over ECDHE; it is
// the closest match to Mozilla's "modern" profile. "default" likewise
// supports TLS 1.2 + 1.3 with AEAD ciphers and is the closest match to
// Mozilla's "intermediate" profile. For "old" we pick "20190214" — a
// fixed (non-deprecating) policy that still negotiates TLS 1.0 / 1.1
// with 3DES and DHE for legacy clients.
const PROFILE_POLICY = {
  'modern':       'default_tls13',
  'intermediate': 'default',
  'old':          '20190214',
};

// PQ-capable named policy. s2n exposes a single stable "default_pq"
// alias which currently negotiates X25519MLKEM768 (hybrid). There is
// no separate "PQ Only" stable policy in s2n today; "PQ Only" mode
// therefore falls back to "default_pq" and the template emits a
// comment noting the limitation.
const PQ_POLICY = 'default_pq';

// First s2n-tls release that exposed the "default_pq" alias.
const PQ_MIN_VERSION = '1.5.0';

export default (form, output) => {
  const protocols = output.protocols;
  const supportsTls13 = protocols.includes('TLSv1.3');
  const profilePolicy = PROFILE_POLICY[form.config] || 'default';

  // If the user deselects TLS 1.3 entirely (e.g. by pinning to an old
  // server version that predates s2n's TLS 1.3 support), do not pick a
  // TLS-1.3-only policy.
  let policy = profilePolicy;
  if (!supportsTls13 && policy === 'default_tls13') {
    policy = 'default';
  }

  // PQ override: any non-"none" PQ mode forces the PQ-capable policy.
  const pqRequested = form.pq && form.pq !== 'none';
  if (pqRequested) {
    policy = PQ_POLICY;
  }

  // Per-template context (see ./ctx.js): every form.* value spliced
  // into the rendered C source string is filtered through safe() as
  // defence in depth — the allow-list keeps the value safe inside both
  // C `/* */` comments and C string literals.
  const ctx = {
    config: safe(form.config),
  };

  let conf =
      '/* '+output.header+' */\n'+
      '/* '+output.link+' */\n'+
      '/*\n'+
      ' * s2n-tls is a C library; this snippet is meant to be embedded in\n'+
      ' * your application. Build with:\n'+
      ' *     cc your_app.c -ls2n -o your_app\n'+
      ' *\n'+
      ' * s2n-tls is configured via named security policies. The Mozilla\n'+
      ' * "'+ctx.config+'" profile maps to the s2n "'+policy+'" policy.\n'+
      ' * See https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch06-security-policies.md\n'+
      ' * for the full list of policies and the protocols / ciphersuites /\n'+
      ' * curves they enable.\n';

  if (form.config === 'old') {
    conf +=
      ' *\n'+
      ' * NOTE: s2n-tls has been steadily removing legacy security policies.\n'+
      ' *       The "20190214" policy still allows TLS 1.0 / 1.1, 3DES, and\n'+
      ' *       DHE for legacy clients, but if it has been deprecated in your\n'+
      ' *       version of s2n-tls you may need to pick a different dated\n'+
      ' *       policy from the security-policies documentation.\n';
  }

  if (pqRequested) {
    conf +=
      ' *\n'+
      ' * Post-Quantum: "default_pq" negotiates the X25519MLKEM768 hybrid PQ\n'+
      ' * key-exchange group when both peers support it, and falls back to\n'+
      ' * classical groups otherwise.\n';
    if (form.pq === 'only') {
      conf +=
      ' * NOTE: s2n-tls does not currently expose a stable "PQ only" named\n'+
      ' *       policy; "default_pq" still allows classical fallback. Treat\n'+
      ' *       this template as best-effort PQ in s2n until upstream adds a\n'+
      ' *       PQ-only policy.\n';
    }
    if (form.serverVersion && !minver(PQ_MIN_VERSION, form.serverVersion)) {
      conf +=
      ' *\n'+
      ' * WARNING: the "default_pq" policy requires s2n-tls '+PQ_MIN_VERSION+' or\n'+
      ' *          newer. Older s2n-tls releases do not implement ML-KEM.\n';
    }
    if (form.config === 'old') {
      // The "old" profile exists to interoperate with pre-TLS-1.2 clients
      // (TLS 1.0 / 1.1, 3DES, DHE). ML-KEM is a TLS 1.3 key-exchange
      // group, so selecting PQ together with "old" is contradictory:
      // "default_pq" does not negotiate the legacy primitives that "old"
      // is meant to enable, and the legacy clients "old" targets cannot
      // negotiate ML-KEM. Warn the user that they must pick one.
      conf +=
      ' *\n'+
      ' * WARNING: the "old" Mozilla profile and Post-Quantum key exchange\n'+
      ' *          are mutually exclusive. ML-KEM is a TLS 1.3 group, and\n'+
      ' *          the "default_pq" policy will NOT negotiate the TLS 1.0 /\n'+
      ' *          1.1 / 3DES / DHE primitives that the "old" profile\n'+
      ' *          exists to enable. Choose either backwards-compatibility\n'+
      ' *          ("old" profile, no PQ) OR forwards-compatibility\n'+
      ' *          (PQ, "intermediate" or "modern" profile) — not both.\n';
    }
  }

  // Informational ciphersuite listing (not rendered into the C config —
  // s2n picks suites internally based on the named policy).
  const suites = []
    .concat(output.cipherSuites || [])
    .concat(output.ciphers || []);
  if (suites.length > 0) {
    conf +=
      ' *\n'+
      ' * For reference, the Mozilla "'+ctx.config+'" profile recommends the\n'+
      ' * following ciphersuites (s2n selects a subset based on the policy):\n';
    for (const c of suites) {
      conf += ' *   - '+c+'\n';
    }
  }

  conf += ' */\n';

  conf +=
      '\n'+
      '#include <stdio.h>\n'+
      '#include <stdlib.h>\n'+
      '#include <s2n.h>\n'+
      '\n'+
      'int main(void) {\n'+
      '    if (s2n_init() != S2N_SUCCESS) {\n'+
      '        fprintf(stderr, "s2n_init: %s\\n", s2n_strerror(s2n_errno, "EN"));\n'+
      '        return EXIT_FAILURE;\n'+
      '    }\n'+
      '\n'+
      '    struct s2n_config *config = s2n_config_new();\n'+
      '    if (config == NULL) {\n'+
      '        fprintf(stderr, "s2n_config_new failed\\n");\n'+
      '        s2n_cleanup();\n'+
      '        return EXIT_FAILURE;\n'+
      '    }\n'+
      '\n'+
      '    /* Load the certificate chain + private key from disk. */\n'+
      '    if (s2n_config_add_cert_chain_and_key_to_store(\n'+
      '            config,\n'+
      '            /* cert_chain_pem_path = */ "/path/to/signed_cert_plus_intermediates",\n'+
      '            /* private_key_pem_path = */ "/path/to/private_key") != S2N_SUCCESS) {\n'+
      '        fprintf(stderr, "load cert: %s\\n", s2n_strerror(s2n_errno, "EN"));\n'+
      '        s2n_config_free(config);\n'+
      '        s2n_cleanup();\n'+
      '        return EXIT_FAILURE;\n'+
      '    }\n'+
      '\n'+
      '    /* Mozilla '+ctx.config+' profile -> s2n named security policy. */\n'+
      '    if (s2n_config_set_cipher_preferences(config, "'+policy+'") != S2N_SUCCESS) {\n'+
      '        fprintf(stderr, "set_cipher_preferences: %s\\n", s2n_strerror(s2n_errno, "EN"));\n'+
      '        s2n_config_free(config);\n'+
      '        s2n_cleanup();\n'+
      '        return EXIT_FAILURE;\n'+
      '    }\n';

  if (form.ocsp) {
    conf +=
      '\n'+
      '    /* Request OCSP stapling from the peer / send stapled responses. */\n'+
      '    if (s2n_config_set_status_request_type(config, S2N_STATUS_REQUEST_OCSP) != S2N_SUCCESS) {\n'+
      '        fprintf(stderr, "set_status_request_type: %s\\n", s2n_strerror(s2n_errno, "EN"));\n'+
      '        s2n_config_free(config);\n'+
      '        s2n_cleanup();\n'+
      '        return EXIT_FAILURE;\n'+
      '    }\n';
  }

  if (form.hsts) {
    conf +=
      '\n'+
      '    /* HSTS is an HTTP-layer concern; when wrapping s2n in an HTTPS\n'+
      '     * server, emit the following response header on TLS responses:\n'+
      '     *     Strict-Transport-Security: max-age='+output.hstsMaxAge+'; includeSubDomains\n'+
      '     */\n';
  }

  conf +=
      '\n'+
      '    /* Use `config` to create per-connection s2n_connection objects:\n'+
      '     *     struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);\n'+
      '     *     s2n_connection_set_config(conn, config);\n'+
      '     *     s2n_connection_set_fd(conn, accepted_socket_fd);\n'+
      '     *     s2n_negotiate(conn, &blocked);\n'+
      '     */\n'+
      '\n'+
      '    s2n_config_free(config);\n'+
      '    s2n_cleanup();\n'+
      '    return EXIT_SUCCESS;\n'+
      '}\n';

  return conf;
};
