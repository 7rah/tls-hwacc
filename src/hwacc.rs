use anyhow::Result;
use crypto_bindings::{
    crypt_auth_op, session_info_op, session_op, COP_DECRYPT, COP_ENCRYPT,
    CRYPTO_AES_GCM, 
};
use nix::{
    fcntl::{fcntl, open, FcntlArg, FdFlag, OFlag},
    ioctl_readwrite,
    sys::stat::Mode,
};

#[derive(Debug, Default)]
pub struct Session {
    fd: i32,
    session_id: u32,
    key: Vec<u8>,
}

pub enum Cipher {
    AesGcm,
    AesCcm,
}

const CRYPTO_AES_CCM: u32 = 51;

#[derive(Debug)]
struct SessionInfo {
    cipher_name: String,
    driver_name: String,
    alignmask: u16,
}

impl Session {
    ioctl_readwrite!(create_session, b'c', 102, session_op);
    ioctl_readwrite!(get_session_info, b'c', 107, session_info_op);
    ioctl_readwrite!(do_aead_encrypt, b'c', 109, crypt_auth_op);

    pub fn new(key: &[u8], cipher: Cipher) -> Result<Self> {
        let key = key.to_vec();

        // Open the device
        let fd = open("/dev/crypto", OFlag::O_RDWR, Mode::empty())?;

        // Set the close-on-exec flag
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

        // Create a new session
        let mut sess = session_op {
            cipher: match cipher {
                Cipher::AesGcm => CRYPTO_AES_GCM,
                Cipher::AesCcm => CRYPTO_AES_CCM,
            },
            keylen: key.len() as u32,
            key: key.as_ptr() as *mut u8,
            ..Default::default()
        };
        let _res = unsafe { Self::create_session(fd, &mut sess) }?; // 不为0时退出

        Ok(Session {
            fd,
            session_id: sess.ses,
            key,
        })
    }

    pub fn get_info(&self) -> Result<SessionInfo> {
        let mut sess_info = session_info_op::default();
        sess_info.ses = self.session_id;
        unsafe { Self::get_session_info(self.fd, &mut sess_info) }?;
        let cipher_name =
            unsafe { std::ffi::CStr::from_ptr(sess_info.cipher_info.cra_name.as_ptr()) }
                .to_str()?
                .to_string();
        let driver_name =
            unsafe { std::ffi::CStr::from_ptr(sess_info.cipher_info.cra_driver_name.as_ptr()) }
                .to_str()?
                .to_string();
        let alignmask = sess_info.alignmask;
        Ok(SessionInfo {
            cipher_name,
            driver_name,
            alignmask,
        })
    }

    pub fn encrypt_in_place(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        buffer.reserve(16); // reserve space for the tag

        let mut aead_crypt = crypt_auth_op {
            ses: self.session_id,
            op: COP_ENCRYPT as u16,

            // nonce
            iv_len: nonce.len() as u32,
            iv: nonce.as_ptr() as *mut u8,

            // additional data
            auth_len: associated_data.len() as u32,
            auth_src: associated_data.as_ptr() as *mut u8,

            // src
            len: buffer.len() as u32,
            src: buffer.as_ptr() as *mut u8,

            // must ensure that the buffer is large enough to hold the ciphertext+tag
            dst: buffer.as_ptr() as *mut u8,

            ..Default::default()
        };

        unsafe { Self::do_aead_encrypt(self.fd, &mut aead_crypt) }?;
        unsafe { buffer.set_len(buffer.len() + 16) } // set the length to include the tag
        Ok(())
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        println!("decrypt size {}", buffer.len());
        if buffer.len() < 16 {
            return Err(anyhow::anyhow!("Buffer too small to contain the tag"));
        }

        let mut aead_crypt = crypt_auth_op {
            ses: self.session_id,
            op: COP_DECRYPT as u16,

            // nonce
            iv_len: nonce.len() as u32,
            iv: nonce.as_ptr() as *mut u8,

            // additional data
            auth_len: associated_data.len() as u32,
            auth_src: associated_data.as_ptr() as *mut u8,

            // src
            len: buffer.len() as u32,
            src: buffer.as_ptr() as *mut u8,

            // must ensure that the buffer is large enough to hold the ciphertext+tag
            dst: buffer.as_ptr() as *mut u8,

            ..Default::default()
        };

        unsafe { Self::do_aead_encrypt(self.fd, &mut aead_crypt) }?;
        unsafe { buffer.set_len(buffer.len() - 16) } // set the length to exclude the tag
        Ok(())
    }
}
