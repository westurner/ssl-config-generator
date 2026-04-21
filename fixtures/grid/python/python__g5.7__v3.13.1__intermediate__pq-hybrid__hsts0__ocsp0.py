# generated 1970-01-01, Mozilla Guideline v5.7, Python (ssl module) 3.13.1, OpenSSL 3.6.1, intermediate config, PQ: hybrid
# https://ssl-config.mozilla.org/#server=python&version=3.13.1&config=intermediate&openssl=3.6.1&guideline=5.7&hsts=false&ocsp=false&pq=hybrid
#
# Python `ssl` module configuration (intermediate profile).
#
# The Python `ssl` module is a thin wrapper around OpenSSL. The
# protocol-version floor, TLSv1.2 cipher list, and (on Python 3.13+)
# group / curve preferences are pinned below via the SSLContext API.
# TLSv1.3 ciphersuites are NOT exposed by Python; they are inherited
# from the system `openssl.cnf` `[system_default_sect]` Ciphersuites
# directive — use the "OpenSSL config (openssl.cnf)" target in this
# tool to set them system-wide.
#
# Requires:
#   - Python >= 3.10 (modern SSLContext API; older 3.x works with
#                     adjustments).
#
# OCSP stapling: server-side OCSP stapling is NOT exposed by
# CPython's `ssl` module (as of 3.13). There is no
# `SSLContext.set_ocsp_response()` and the `SSL_CTX_set_tlsext_status_cb`
# OpenSSL hook is not wrapped. The `cryptography` package can
# parse OCSP responses (`cryptography.x509.ocsp`) but does not
# wire them into an SSLContext for stapling. PEP 543 (a unified
# TLS API that would have included stapling hooks) was deferred.
# Recommendation: terminate TLS in a fronting reverse proxy that
# staples (nginx / HAProxy / Caddy — see those targets in this
# tool), or refresh a <cert>.ocsp file out-of-band (cron +
# `openssl ocsp -respout`) and serve the Python app behind a
# stapling-aware proxy.
#   - Python >= 3.13 for SSLContext.set_groups(); earlier versions
#                     can pin a single curve via set_ecdh_curve()
#                     (see fallback below) or rely on openssl.cnf.
#   - OpenSSL >= 3.5 for built-in ML-KEM hybrid groups
#                     (X25519MLKEM768, SecP256r1MLKEM768,
#                     SecP384r1MLKEM1024). Inspect with:
#                         python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"

import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3

context.load_cert_chain(
    certfile="/path/to/signed_cert_plus_intermediates",
    keyfile="/path/to/private_key",
)

# TLSv1.2 (and earlier) cipher list (OpenSSL syntax).
context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305")

# Key-exchange groups (a.k.a. "curves") in preference order.
# ML-KEM hybrid groups (X25519MLKEM768, SecP256r1MLKEM768,
# SecP384r1MLKEM1024) are TLS 1.3-only (key_share extension); a
# TLS 1.2 connection silently advertises none of them.
# Hybrid PQ mode: ML-KEM hybrid groups are listed first, with
# classical curves retained for interoperability with peers that
# do not yet implement post-quantum key exchange. Note that a MITM
# capable of stripping the hybrid group from ClientHello can still
# downgrade the connection to a classical group; PQ-only mode
# eliminates that risk at the cost of interoperability.
try:
    # Python 3.13+: full multi-group preference list.
    context.set_groups("X25519:prime256v1:secp384r1")
except AttributeError:
    # Python < 3.13: only a single curve can be pinned via the API.
    # For a full PQ-aware group list on older interpreters, configure
    # the system openssl.cnf [system_default_sect] Groups directive.
    context.set_ecdh_curve("X25519")

# Wrap a TCP socket and serve. The `ssl` module itself does not
# emit HTTP headers; HSTS must be set by the HTTP layer above.
import socket
with socket.create_server(("0.0.0.0", 443)) as sock:
    with context.wrap_socket(sock, server_side=True) as ssock:
        # Accept connections, dispatch to your handler, etc.
        pass
