use rustls::crypto::cipher::{self, AeadKey, Iv, UnsupportedOperationError};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

use crate::gcm;
use crate::gcm::Aes256Gcm;

pub struct Tls13Aes256Gcm;

impl cipher::Tls13AeadAlgorithm for Tls13Aes256Gcm {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Tls13CipherAes256Gcm(
            Aes256Gcm::new(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Tls13CipherAes256Gcm(
            Aes256Gcm::new(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        32 // aes-256-gcm key length
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

struct Tls13CipherAes256Gcm(gcm::Aes256Gcm, cipher::Iv);

impl cipher::MessageEncrypter for Tls13CipherAes256Gcm {
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

        let tag = self
            .0
            .encrypt_in_place(&nonce, &aad, &mut payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(&tag);

        Ok(cipher::OpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AES256GCM_OVERHEAD
    }
}

impl cipher::MessageDecrypter for Tls13CipherAes256Gcm {
    fn decrypt(
        &mut self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = m.payload_mut();
        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(payload.len());

        let tag = payload.split_off(payload.len() - 16);

        self.0
            .decrypt_in_place(&nonce, &aad, payload, &tag.try_into().unwrap())
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

const AES256GCM_OVERHEAD: usize = 16;
