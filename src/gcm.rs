use crate::hwacc::Session;
use anyhow::Result;
use constant_time_eq::constant_time_eq;

pub trait Aes {
    fn new(key: &[u8]) -> Self;
    fn apply_in_place(&self, buffer: &mut [u8]);
}

pub trait GHash {
    fn new(key: &[u8]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 16];
}

pub trait AesCtr {
    fn new(key: &[u8]) -> Result<Self>
    where
        Self: Sized;
    fn apply_in_place(&self, iv: &[u8; 16], data: &mut [u8]) -> Result<()>;
}

impl Aes for crypto2::blockcipher::Aes256 {
    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }
    fn apply_in_place(&self, buffer: &mut [u8]) {
        self.encrypt(buffer);
    }
}

impl GHash for crypto2::mac::GHash {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 16];
        k.copy_from_slice(&key[..16]);
        Self::new(&k)
    }
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }
    fn finalize(self) -> [u8; 16] {
        self.finalize()
    }
}

pub struct Aes256Ctr {
    session: Session,
}

impl AesCtr for Aes256Ctr {
    fn new(key: &[u8]) -> Result<Self> {
        let session = Session::new(key, crate::hwacc::Cipher::AesCtr)?;
        Ok(Self { session })
    }
    fn apply_in_place(&self, iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
        self.session.crypt(iv, data)
    }
}

pub struct AesGcm<AesEnc: Aes, Gmac: GHash + Clone, Ctr: AesCtr> {
    ghash: Gmac,
    aes: AesEnc,
    ctr: Ctr,
}

pub type Aes256Gcm = AesGcm<crypto2::blockcipher::Aes256, crypto2::mac::GHash, Aes256Ctr>;

impl<AesEnc: Aes, Gmac: GHash + Clone, Ctr: AesCtr> AesGcm<AesEnc, Gmac, Ctr> {
    pub fn new(key: &[u8]) -> Result<Self> {
        let aes = AesEnc::new(key);
        let ctr = Ctr::new(key)?;

        // compute h
        let mut h = [0u8; 16];
        aes.apply_in_place(&mut h);
        let ghash = Gmac::new(&h);

        Ok(Self { ghash, aes, ctr })
    }

    fn compute_gmac(&self, nonce: &[u8; 12], aad: &[u8], buffer: &[u8]) -> [u8; 16] {
        let mut ghash = self.ghash.clone();

        let mut octets = [0u8; 16];
        octets[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        octets[8..16].copy_from_slice(&((buffer.len() as u64) * 8).to_be_bytes());

        ghash.update(aad);
        ghash.update(buffer);
        ghash.update(&octets);
        let code = ghash.finalize();

        let base_ectr = {
            let mut base_ectr = [0u8; 16];
            base_ectr[..12].copy_from_slice(nonce);
            base_ectr[15] = 1;

            self.aes.apply_in_place(&mut base_ectr);
            base_ectr
        };

        let mut gmac = [0u8; 16];
        for i in 0..16 {
            gmac[i] = code[i] ^ base_ectr[i];
        }

        gmac
    }

    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16]> {
        // ctr encrypt
        {
            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(nonce);
            iv[15] = 2;

            self.ctr.apply_in_place(&iv, buffer)?;
        }

        Ok(self.compute_gmac(nonce, aad, buffer))
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        if !constant_time_eq(&self.compute_gmac(nonce, aad, buffer), tag) {
            anyhow::bail!("invalid tag");
        }

        // ctr decrypt
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 2;

        self.ctr.apply_in_place(&iv, buffer)?;

        Ok(())
    }
}
