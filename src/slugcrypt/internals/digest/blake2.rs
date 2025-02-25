use blake2::*;
use blake2::Digest;
use blake2::digest::{Update,VariableOutput};

pub struct SlugBlake2bHasher(usize);
pub struct SlugBlake2sHasher(usize);

impl SlugBlake2bHasher {
    pub fn new(size: usize) -> Self {
        if size >= 1usize && size <= 64usize {
            Self(size)
        } else {
            return Self(48usize)
        }
    }
    pub fn hash<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let mut hasher = blake2::Blake2bVar::new(self.0).unwrap();
        hasher.update(data.as_ref());

        let mut out = vec![0u8; self.0];
        let result = hasher.finalize_variable(&mut out);
        return out
    }
}

impl SlugBlake2sHasher {
    pub fn new(size: usize) -> Self {
        if size >= 1usize && size <= 32usize {
            Self(size)
        } else {
            return Self(32usize)
        }
    }
    pub fn hash<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let mut hasher = blake2::Blake2sVar::new(self.0).unwrap();
        hasher.update(data.as_ref());

        let mut out = vec![0u8; self.0];
        let result = hasher.finalize_variable(&mut out);
        return out
    }
    pub fn thumbprint<T: AsRef<[u8]>>(&self, data: T) {
        let thumbprint = Self::new(8usize);
        thumbprint.hash(data.as_ref());
    }
}