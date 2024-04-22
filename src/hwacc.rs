use anyhow::Result;
use crypto_bindings::{crypt_op, session_info_op, session_op, COP_ENCRYPT, CRYPTO_AES_CTR};
use nix::{
    fcntl::{fcntl, open, FcntlArg, FdFlag, OFlag},
    ioctl_readwrite,
    sys::stat::Mode,
};

#[derive(Debug, Default)]
pub struct Session {
    fd: i32,
    session_id: u32,
}

pub enum Cipher {
    AesCtr,
}

#[derive(Debug)]
#[allow(dead_code)]
struct SessionInfo {
    cipher_name: String,
    driver_name: String,
    alignmask: u16,
}

impl Session {
    ioctl_readwrite!(create_session, b'c', 102, session_op);
    ioctl_readwrite!(get_session_info, b'c', 107, session_info_op);
    ioctl_readwrite!(do_crypt, b'c', 104, crypt_op);

    pub fn new(key: &[u8], cipher: Cipher) -> Result<Self> {
        // Open the device
        let fd = open("/dev/crypto", OFlag::O_RDWR, Mode::empty())?;

        // Set the close-on-exec flag
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

        // Create a new session
        let mut sess = session_op {
            cipher: match cipher {
                Cipher::AesCtr => CRYPTO_AES_CTR,
            },
            keylen: key.len() as u32,
            key: key.as_ptr() as *mut u8,
            ..Default::default()
        };
        let _res = unsafe { Self::create_session(fd, &mut sess) }?; // 不为0时退出

        Ok(Session {
            fd,
            session_id: sess.ses,
        })
    }

    fn get_info(&self) -> Result<SessionInfo> {
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

    pub fn crypt(&self, iv: &[u8; 16], buffer: &mut [u8]) -> Result<()> {
        let mut crypt_op = crypt_op {
            ses: self.session_id,
            len: buffer.len() as u32,
            src: buffer.as_ptr() as *mut u8,
            dst: buffer.as_mut_ptr(),
            iv: iv.as_ptr() as *mut u8,
            op: COP_ENCRYPT as u16,
            mac: std::ptr::null_mut(),
            flags: 0,
        };

        unsafe { Self::do_crypt(self.fd, &mut crypt_op) }?;
        Ok(())
    }
}
