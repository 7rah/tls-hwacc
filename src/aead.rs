use rustls::crypto::cipher::{self, AeadKey, Iv, UnsupportedOperationError};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use crate::hwacc;

pub struct Aes128Gcm;

impl cipher::Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Tls13Cipher(
            hwacc::Session::new(key.as_ref(), hwacc::Cipher::AesGcm).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Tls13Cipher(
            hwacc::Session::new(key.as_ref(), hwacc::Cipher::AesGcm).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        16 // aes-128-gcm key length
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

struct Tls13Cipher(hwacc::Session, cipher::Iv);

impl cipher::MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        // construct a TLSInnerPlaintext
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);
        payload.push(m.typ.get_u8());

        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(total_len);

        let ret = self
            .0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| {
                cipher::OpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            });

        ret
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl cipher::MessageDecrypter for Tls13Cipher {
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        //println!("seq start {seq}");
        let payload = m.payload_mut();

        //println!("encrypt {} {}", payload.len(), seq);

        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, payload)
            .map_err(|_| rustls::Error::DecryptError)?;

        //println!("seq finish {seq}");
        m.into_tls13_unpadded_message()
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
