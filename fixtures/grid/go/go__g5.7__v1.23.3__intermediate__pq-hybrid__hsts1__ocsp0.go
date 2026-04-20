// generated 1970-01-01, Mozilla Guideline v5.7, Go 1.23.3, intermediate config, PQ: hybrid, HSTS
// https://ssl-config.mozilla.org/#server=go&version=1.23.3&config=intermediate&guideline=5.7&hsts=true&ocsp=false&pq=hybrid
package main

import (
    "crypto/tls"
    "log"
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Write([]byte("This server is running the Mozilla intermediate configuration.\n"))
    })

    go func() {
        redirectToHTTPS := func(w http.ResponseWriter, req *http.Request) {
            http.Redirect(w, req, "https://"+req.Host+req.RequestURI, http.StatusMovedPermanently)
        }
        srv := &http.Server{
            Handler:     http.HandlerFunc(redirectToHTTPS),
            ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second,
        }
        log.Fatal(srv.ListenAndServe())
    }()

    // Due to a lack of DHE support, you -must- use an ECDSA cert to support IE 11 on Windows 7
    cfg := &tls.Config{
        MinVersion: tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{
            tls.X25519,               // Go 1.8+
            tls.CurveP256,
            tls.CurveP384,
        },
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
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
