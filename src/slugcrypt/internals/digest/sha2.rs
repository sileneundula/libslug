//! # SHA2
//! 
//! SHA2 is a standard hash function widely used in the industry, specifically SHA256. This module contains SHA2 with the sizes of {224,256,384,512} bits.
//! 
//! SHA2 is generally regarded as one of the most used hash functions and has reliability through its long usage.

use sha2::Digest;
use sha2::Sha384;
use sha2::Sha512;

/// # SHA2 Hasher
/// 
/// SHA2 Hashing Instance of Different Sizes (256,384,512)
pub struct Sha2Hasher(usize);

enum Hasher {
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Sha2Hasher {
    pub fn new(size: usize) -> Self {
        match size {
            384 => Self(384),
            512 => Self(512),
            _ => Self(512),
        }
    }
    
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = match self.0 {
            384usize => Hasher::Sha384(Sha384::new()),
            512usize => Hasher::Sha512(Sha512::new()),
            _ => Hasher::Sha512(Sha512::new()),
        };
        match &mut hasher {
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
        let result: Vec<u8> = match hasher {
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        };
        return result
    }
}