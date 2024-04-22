use rustls::crypto::hash;
use sha2::Digest;

pub struct Sha384;

impl hash::Hash for Sha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha384Context(sha2::Sha384::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2::Sha384::digest(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha384Context(sha2::Sha384);

impl hash::Context for Sha384Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha384Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
