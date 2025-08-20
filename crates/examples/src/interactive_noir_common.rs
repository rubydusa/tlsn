use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::CryptoProvider;

pub fn crypto_provider() -> CryptoProvider {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    }
}

