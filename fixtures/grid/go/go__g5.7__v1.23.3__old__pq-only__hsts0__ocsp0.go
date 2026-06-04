// generated 1970-01-01, TLSRef Guideline v5.7, Go 1.23.3, old config, PQ: only
// https://ssl-config.mozilla.org/#server=go&version=1.23.3&config=old&guideline=5.7&hsts=false&ocsp=false&pq=only
package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("This server is running the TLSRef old configuration.\n"))
    })

    cfg := &tls.Config{
        MinVersion: tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.X25519MLKEM768,       // Go 1.24+
        },
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        },
    }

    srv := &http.Server{
        Addr:      ":443",
        Handler:   mux,
        TLSConfig: cfg,
        // Consider setting ReadTimeout, WriteTimeout, and IdleTimeout
        // to prevent connections from taking resources indefinitely.
    }

    log.Fatal(srv.ListenAndServeTLS(
        "/path/to/signed_cert_plus_intermediates",
        "/path/to/private_key",
    ))
}
