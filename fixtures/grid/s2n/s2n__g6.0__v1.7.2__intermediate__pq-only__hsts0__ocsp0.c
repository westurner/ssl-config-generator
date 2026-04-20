/* generated 1970-01-01, Mozilla Guideline v6.0, s2n-tls 1.7.2, intermediate config, PQ: only */
/* https://ssl-config.mozilla.org/#server=s2n&version=1.7.2&config=intermediate&guideline=6.0&hsts=false&ocsp=false&pq=only */
/*
 * s2n-tls is a C library; this snippet is meant to be embedded in
 * your application. Build with:
 *     cc your_app.c -ls2n -o your_app
 *
 * s2n-tls is configured via named security policies. The Mozilla
 * "intermediate" profile maps to the s2n "default_pq" policy.
 * See https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch06-security-policies.md
 * for the full list of policies and the protocols / ciphersuites /
 * curves they enable.
 *
 * Post-Quantum: "default_pq" negotiates the X25519MLKEM768 hybrid PQ
 * key-exchange group when both peers support it, and falls back to
 * classical groups otherwise.
 * NOTE: s2n-tls does not currently expose a stable "PQ only" named
 *       policy; "default_pq" still allows classical fallback. Treat
 *       this template as best-effort PQ in s2n until upstream adds a
 *       PQ-only policy.
 *
 * For reference, the Mozilla "intermediate" profile recommends the
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

    /* Mozilla intermediate profile -> s2n named security policy. */
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
