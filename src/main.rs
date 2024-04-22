use aes_gcm::AeadInPlace;
use pki_types::ServerName;
use rustls::SupportedCipherSuite;
use std::io;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, stdout, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

mod aead;
mod gcm;
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
    let server_addr = "127.0.0.1:4444";
    let domain = "example.com";
    let mut tls_stream = build_tls_stream(server_addr, domain).await;

    // 双向转发
    let _ = copy_bidirectional(&mut tcp_stream, &mut tls_stream).await;
}

fn bench() {
    let key: &[u8; 32] = &[42; 32];
    let nonce = [1u8; 12];
    let aad = [1u8; 16];
    let mut buffer = [1u8; 16];

    {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
            Key, // Or `Aes128Gcm`
            Nonce,
        };
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);
        let mut buffer: Vec<u8> = buffer.to_vec();

        cipher
            .encrypt_in_place(&nonce.into(), aad.as_slice(), &mut buffer)
            .unwrap();
        println!("aes_gcm: {:x?}", buffer);
    }

    {
        use gcm::Aes256Gcm;
        let mut buffer: Vec<u8> = buffer.to_vec();

        let gcm = gcm::Aes256Gcm::new(key.as_ref()).unwrap();
        let tag = gcm.encrypt_in_place(&nonce, &aad, &mut buffer).unwrap();
        buffer.extend_from_slice(&tag);
        println!("gcm: {:x?} ", buffer);
    }
}

pub fn gcm_benchmark() {
    let key = [1u8; 32];
    let nonce = [1u8; 12];
    let aad = [1u8; 0];
    let mut buffer = [1u8; 8192];
    let gcm = gcm::Aes256Gcm::new(&key).unwrap();

    // 加密测速
    let start = std::time::Instant::now();
    let cnt = 10000;
    for _ in 0..cnt {
        gcm.encrypt_in_place(&nonce, &aad, &mut buffer).unwrap();
    }
    let elapsed = start.elapsed();
    // 计算 MB/s，每次加密 8192 字节
    let speed = (cnt as f64 * 8192.0 / 1024.0 / 1024.0) / (elapsed.as_secs_f64());
    println!("encrypt speed: {} MB/s", speed);
}

#[tokio::main]
async fn main() {
    //bench();
    //bench().await;
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

use rustls::crypto::ring::tls13::{AeadAlgorithm, Aes256GcmAead};
//use rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384 as OtherTLS13_AES_256_GCM_SHA384;
use crate::hwacc::Cipher;


pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::Sha384,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha384Hmac),
        aead_alg: &aead::Tls13Aes256Gcm,
        quic: None,
    });

pub static CUSTOM: &[SupportedCipherSuite] = &[TLS13_AES_256_GCM_SHA384];

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: CUSTOM.to_vec(),
        ..rustls::crypto::ring::default_provider()
    }
}
