// generated 1970-01-01, Mozilla Guideline v5.7, Rust (rustls) 0.23.18, intermediate config, PQ: none
// https://ssl-config.mozilla.org/#server=rust&version=0.23.18&config=intermediate&guideline=5.7&pq=none
//
// Cargo.toml:
//     [dependencies]
//     rustls = { version = "0.23", features = ["aws-lc-rs"] }
//     rustls-pemfile = "2"
//
// rustls negotiates X25519MLKEM768 (hybrid PQ) automatically with
// the aws-lc-rs provider when both peers support it. Curve / cipher
// preference lists are not user-configurable in rustls; they are
// picked by the chosen CryptoProvider. This template selects only
// the protocol versions and certificate material.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::{ServerConfig, version};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls_pemfile::{certs, pkcs8_private_keys};

fn load_certs(path: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut reader = BufReader::new(File::open(path).expect("cert file"));
    certs(&mut reader).filter_map(Result::ok).collect()
}

fn load_key(path: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    let mut reader = BufReader::new(File::open(path).expect("key file"));
    let mut keys: Vec<_> = pkcs8_private_keys(&mut reader).filter_map(Result::ok).collect();
    rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0))
}

fn main() {
    // intermediate configuration
    let provider = Arc::new(default_provider());
    let versions: &[&'static rustls::SupportedProtocolVersion] = &[
        &version::TLS13,
        &version::TLS12,
    ];

    let certs = load_certs("/path/to/signed_cert_plus_intermediates");
    let key = load_key("/path/to/private_key");

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("inconsistent protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("bad cert/key");

    let _config = Arc::new(config);

    // Bind your TCP listener to :443 and feed accepted streams
    // into rustls::ServerConnection / tokio_rustls::TlsAcceptor
    // (depending on your runtime) using `_config`.
}
