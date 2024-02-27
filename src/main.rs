use pki_types::ServerName;
use rustls::crypto::ring;
use rustls::SupportedCipherSuite;
use std::io;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

mod aead;
mod hash;
mod hmac;
mod hwacc;

async fn build_tls_stream(addr: &str, domain: &str) -> TlsStream<TcpStream> {
    //config
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await.unwrap();

    let domain = ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
        .unwrap()
        .to_owned();
    connector.connect(domain, stream).await.unwrap()
}

async fn process(mut tcp_stream: TcpStream) {
    //let server_addr = "127.0.0.1:4444";
    let server_addr = "221.131.165.117:14621";
    let domain = "icable-ddns.nodenet.cloud";
    let mut tls_stream = build_tls_stream(server_addr, domain).await;

    // 双向转发
    let _ = copy_bidirectional(&mut tcp_stream, &mut tls_stream).await;
}

#[tokio::main]
async fn main() {
    // 监听本地端口

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            println!("accept a socket: {:?}", socket);
            process(socket).await;
        });
    }
}

static TLS13_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: 1 << 23,
            integrity_limit: 1 << 52,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aes128Gcm,
        quic: None,
    });

pub static CUSTOM: &[SupportedCipherSuite] = &[TLS13_AES_128_GCM_SHA256];

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: CUSTOM.to_vec(),
        ..ring::default_provider()
    }
}
