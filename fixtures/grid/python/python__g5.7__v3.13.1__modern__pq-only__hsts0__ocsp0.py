# generated 1970-01-01, Mozilla Guideline v5.7, Python (ssl module) 3.13.1, OpenSSL 3.6.1, modern config, PQ: only
# https://ssl-config.mozilla.org/#server=python&version=3.13.1&config=modern&openssl=3.6.1&guideline=5.7&pq=only
#
# Python `ssl` module configuration (modern profile).
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
#   - Python >= 3.13 for SSLContext.set_groups(); earlier versions
#                     can pin a single curve via set_ecdh_curve()
#                     (see fallback below) or rely on openssl.cnf.
#   - OpenSSL >= 3.5 for built-in ML-KEM hybrid groups
#                     (X25519MLKEM768, SecP256r1MLKEM768,
#                     SecP384r1MLKEM1024). Inspect with:
#                         python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"

import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3

context.load_cert_chain(
    certfile="/path/to/signed_cert_plus_intermediates",
    keyfile="/path/to/private_key",
)

# Key-exchange groups (a.k.a. "curves") in preference order.
# ML-KEM hybrid groups (X25519MLKEM768, SecP256r1MLKEM768,
# SecP384r1MLKEM1024) are TLS 1.3-only (key_share extension); a
# TLS 1.2 connection silently advertises none of them.
# PQ-only mode: classical curves are intentionally omitted, and
# minimum_version is pinned to TLSv1_3 above to prevent a silent
# TLS 1.2 fallback from negotiating classical-only key exchange.
try:
    # Python 3.13+: full multi-group preference list.
    context.set_groups("X25519MLKEM768")
except AttributeError:
    # Python < 3.13 cannot express a multi-group preference list,
    # and set_ecdh_curve() rejects ML-KEM hybrid names. Silently
    # falling back to a classical single curve here would defeat
    # PQ-only mode, so raise loudly. Upgrade Python to 3.13+, or
    # configure groups system-wide via openssl.cnf [system_default_sect]
    # Groups (see the "OpenSSL config (openssl.cnf)" target).
    raise RuntimeError(
        "PQ-only mode requires Python >= 3.13 (SSLContext.set_groups); "
        "set_ecdh_curve() cannot express ML-KEM hybrid groups. "
        "Configure groups via openssl.cnf instead."
    )

# Wrap a TCP socket and serve. The `ssl` module itself does not
# emit HTTP headers; HSTS must be set by the HTTP layer above.
import socket
with socket.create_server(("0.0.0.0", 443)) as sock:
    with context.wrap_socket(sock, server_side=True) as ssock:
        # Accept connections, dispatch to your handler, etc.
        pass
