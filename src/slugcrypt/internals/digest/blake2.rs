//! # BLAKE2 Hash Function (RFC7693)
//! 
//! The BLAKE2 Hash Function (RFC7693) is a well-designed, versatile hash function that is included in libslug. It offers variable digest lengths, keyed-hashing, and many properties.
//! 
//! There are two flavors of BLAKE2:
//! 
//! 1. BLAKE2b (1-64 bytes)
//! 2. BLAKE2s (1-32 bytes) (works best on systems that more low level)
//! 
//! ## Developer Notes
//! 
//! The usize uses size in bytes, being 1-64 for BLAKE2B and 1-32 for BLAKE2s. If an invalid size is provided, a 48 byte digest is generated.
//! 
//! ## TODO
//! 
//! [X] BLAKE2
//!     [ ] BLAKE2B
//!         [X] Digest
//!         [X] Variable Digest
//!         [ ] Keyed-Hashing
//!     [ ] BLAKE2S
//!         [X] Digest
//!         [X] Variable Digest
//!         [ ] Keyed-Hashing

use blake2::*;
use blake2::Digest;
use blake2::digest::{Update,VariableOutput};
use super::digest::SlugDigest;

/// # BLAKE2B Hasher
/// 
/// The BLAKE2B Hasher is used to create a new instance of a hasher. Its usize is used to determine the size of the output in bytes/bits from 1-64 bytes.
pub struct SlugBlake2bHasher(usize);

/// # BLAKE2S Hasher
/// 
/// The BLAKE2S Hasher is used to create a new instance of a hasher. Its usize is used to determine the size of the output in bytes/bits from 1-32 bytes.
pub struct SlugBlake2sHasher(usize);

impl SlugBlake2bHasher {
    /// Initialize Blake2b with the size in bytes (1-64)
    pub fn new(size: usize) -> Self {
        if size >= 1usize && size <= 64usize {
            Self(size)
        } else {
            return Self(48usize)
        }
    }
    /// Hash the input (this does not progressly hash, it just hashes once)
    pub fn update<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let mut hasher = blake2::Blake2bVar::new(self.0).unwrap();
        hasher.update(data.as_ref());

        let mut out = vec![0u8; self.0];
        let result = hasher.finalize_variable(&mut out);
        return out
    }
}

impl SlugBlake2sHasher {
    /// Initialize Blake2s with the size in bytes (1-32 bytes)
    pub fn new(size: usize) -> Self {
        if size >= 1usize && size <= 32usize {
            Self(size)
        } else {
            return Self(32usize)
        }
    }
    /// Hash the input
    pub fn update<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let mut hasher = blake2::Blake2sVar::new(self.0).unwrap();
        hasher.update(data.as_ref());

        let mut out = vec![0u8; self.0];
        let result = hasher.finalize_variable(&mut out);
        return out
    }
    pub fn hash_224<T: AsRef<[u8]>>(data: T) -> [u8;28] {
        let mut hasher = blake2::Blake2sVar::new(28).unwrap();
        hasher.update(data.as_ref());

        let mut out = [0u8; 28];
        let result = hasher.finalize_variable(&mut out);
        return out
    }
    /// Thumbprint is 8 bytes in size
    pub fn thumbprint<T: AsRef<[u8]>>(&self, data: T) {
        let thumbprint = Self::new(8usize);
        thumbprint.update(data.as_ref());
    }
}