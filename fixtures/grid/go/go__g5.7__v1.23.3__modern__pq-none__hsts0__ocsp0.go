// generated 1970-01-01, Mozilla Guideline v5.7, Go 1.23.3, modern config, PQ: none
// https://ssl-config.mozilla.org/#server=go&version=1.23.3&config=modern&guideline=5.7&pq=none
package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("This server is running the Mozilla modern configuration.\n"))
    })

    cfg := &tls.Config{
        MinVersion: tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.X25519,               // Go 1.8+
            tls.CurveP256,
            tls.CurveP384,
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
