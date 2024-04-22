use hmac::{Hmac, Mac};
use rustls::crypto;
use sha2::{Digest, Sha384};

pub struct Sha384Hmac;

impl crypto::hmac::Hmac for Sha384Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha384HmacKey(Hmac::<Sha384>::new_from_slice(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        Sha384::output_size()
    }
}

struct Sha384HmacKey(Hmac<Sha384>);

impl crypto::hmac::Key for Sha384HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        Sha384::output_size()
    }
}
