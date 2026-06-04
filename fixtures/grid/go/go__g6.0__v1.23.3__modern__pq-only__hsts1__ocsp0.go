// generated 1970-01-01, TLSRef Guideline v6.0, Go 1.23.3, modern config, PQ: only, HSTS
// https://ssl-config.mozilla.org/#server=go&version=1.23.3&config=modern&guideline=6.0&hsts=true&ocsp=false&pq=only
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
        w.Write([]byte("This server is running the TLSRef modern configuration.\n"))
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

    cfg := &tls.Config{
        MinVersion: tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.X25519MLKEM768,       // Go 1.24+
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
