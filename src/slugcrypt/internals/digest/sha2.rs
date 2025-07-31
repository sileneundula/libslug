//! # SHA2
//! 
//! SHA2 is a standard hash function widely used in the industry, specifically SHA256. This module contains SHA2 with the sizes of {224,256,384,512} bits.
//! 
//! For security, SHA384 is widely regarded as secure against length extension attacks. SHA512 is widely used as well.
//! 
//! SHA2 is generally regarded as one of the most used hash functions and has reliability through its long usage.

use sha2::Digest;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;

/// # SHA2 Hasher
/// 
/// SHA2 Hashing Instance of Different Sizes (256,384,512)
pub struct Sha2Hasher(usize);

enum Hasher {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Sha2Hasher {
    /// New SHA2 Instance (224*, 256, 384*, 512)
    pub fn new(size: usize) -> Self {
        match size {
            224 => Self(224),
            256 => Self(256),
            384 => Self(384),
            512 => Self(512),
            _ => Self(512),
        }
    }
    /// Update Hash Function and Output Bytes
    pub fn update(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = match self.0 {
            224usize => Hasher::Sha224(Sha224::new()),
            256usize => Hasher::Sha256(Sha256::new()),
            384usize => Hasher::Sha384(Sha384::new()),
            512usize => Hasher::Sha512(Sha512::new()),
            _ => Hasher::Sha512(Sha512::new()),
        };
        match &mut hasher {
            Hasher::Sha224(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
        let result: Vec<u8> = match hasher {
            Hasher::Sha224(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        };
        return result
    }
}