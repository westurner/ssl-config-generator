/* generated 1970-01-01, Mozilla Guideline v5.7, s2n-tls 1.7.2, old config, PQ: only */
/* https://ssl-config.mozilla.org/#server=s2n&version=1.7.2&config=old&guideline=5.7&pq=only */
/*
 * s2n-tls is a C library; this snippet is meant to be embedded in
 * your application. Build with:
 *     cc your_app.c -ls2n -o your_app
 *
 * s2n-tls is configured via named security policies. The Mozilla
 * "old" profile maps to the s2n "default_pq" policy.
 * See https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch06-security-policies.md
 * for the full list of policies and the protocols / ciphersuites /
 * curves they enable.
 *
 * NOTE: s2n-tls has been steadily removing legacy security policies.
 *       The "20190214" policy still allows TLS 1.0 / 1.1, 3DES, and
 *       DHE for legacy clients, but if it has been deprecated in your
 *       version of s2n-tls you may need to pick a different dated
 *       policy from the security-policies documentation.
 *
 * Post-Quantum: "default_pq" negotiates the X25519MLKEM768 hybrid PQ
 * key-exchange group when both peers support it, and falls back to
 * classical groups otherwise.
 * NOTE: s2n-tls does not currently expose a stable "PQ only" named
 *       policy; "default_pq" still allows classical fallback. Treat
 *       this template as best-effort PQ in s2n until upstream adds a
 *       PQ-only policy.
 *
 * WARNING: the "old" Mozilla profile and Post-Quantum key exchange
 *          are mutually exclusive. ML-KEM is a TLS 1.3 group, and
 *          the "default_pq" policy will NOT negotiate the TLS 1.0 /
 *          1.1 / 3DES / DHE primitives that the "old" profile
 *          exists to enable. Choose either backwards-compatibility
 *          ("old" profile, no PQ) OR forwards-compatibility
 *          (PQ, "intermediate" or "modern" profile) — not both.
 *
 * For reference, the Mozilla "old" profile recommends the
 * following ciphersuites (s2n selects a subset based on the policy):
 *   - TLS_AES_128_GCM_SHA256
 *   - TLS_AES_256_GCM_SHA384
 *   - TLS_CHACHA20_POLY1305_SHA256
 *   - ECDHE-ECDSA-AES128-GCM-SHA256
 *   - ECDHE-RSA-AES128-GCM-SHA256
 *   - ECDHE-ECDSA-AES256-GCM-SHA384
 *   - ECDHE-RSA-AES256-GCM-SHA384
 *   - ECDHE-ECDSA-CHACHA20-POLY1305
 *   - ECDHE-RSA-CHACHA20-POLY1305
 *   - DHE-RSA-AES128-GCM-SHA256
 *   - DHE-RSA-AES256-GCM-SHA384
 *   - DHE-RSA-CHACHA20-POLY1305
 *   - ECDHE-ECDSA-AES128-SHA256
 *   - ECDHE-RSA-AES128-SHA256
 *   - ECDHE-ECDSA-AES128-SHA
 *   - ECDHE-RSA-AES128-SHA
 *   - ECDHE-ECDSA-AES256-SHA384
 *   - ECDHE-RSA-AES256-SHA384
 *   - ECDHE-ECDSA-AES256-SHA
 *   - ECDHE-RSA-AES256-SHA
 *   - DHE-RSA-AES128-SHA256
 *   - DHE-RSA-AES256-SHA256
 *   - AES128-GCM-SHA256
 *   - AES256-GCM-SHA384
 *   - AES128-SHA256
 *   - AES256-SHA256
 *   - AES128-SHA
 *   - AES256-SHA
 *   - DES-CBC3-SHA
 */

#include <stdio.h>
#include <stdlib.h>
#include <s2n.h>

int main(void) {
    if (s2n_init() != S2N_SUCCESS) {
        fprintf(stderr, "s2n_init: %s\n", s2n_strerror(s2n_errno, "EN"));
        return EXIT_FAILURE;
    }

    struct s2n_config *config = s2n_config_new();
    if (config == NULL) {
        fprintf(stderr, "s2n_config_new failed\n");
        s2n_cleanup();
        return EXIT_FAILURE;
    }

    /* Load the certificate chain + private key from disk. */
    if (s2n_config_add_cert_chain_and_key_to_store(
            config,
            /* cert_chain_pem_path = */ "/path/to/signed_cert_plus_intermediates",
            /* private_key_pem_path = */ "/path/to/private_key") != S2N_SUCCESS) {
        fprintf(stderr, "load cert: %s\n", s2n_strerror(s2n_errno, "EN"));
        s2n_config_free(config);
        s2n_cleanup();
        return EXIT_FAILURE;
    }

    /* Mozilla old profile -> s2n named security policy. */
    if (s2n_config_set_cipher_preferences(config, "default_pq") != S2N_SUCCESS) {
        fprintf(stderr, "set_cipher_preferences: %s\n", s2n_strerror(s2n_errno, "EN"));
        s2n_config_free(config);
        s2n_cleanup();
        return EXIT_FAILURE;
    }

    /* Use `config` to create per-connection s2n_connection objects:
     *     struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
     *     s2n_connection_set_config(conn, config);
     *     s2n_connection_set_fd(conn, accepted_socket_fd);
     *     s2n_negotiate(conn, &blocked);
     */

    s2n_config_free(config);
    s2n_cleanup();
    return EXIT_SUCCESS;
}
