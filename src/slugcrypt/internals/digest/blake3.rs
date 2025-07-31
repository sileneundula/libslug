//! # BLAKE3
//! 
//! BLAKE3 is a hash function that is efficient, collision-resistant, and blazingly fast. It is generally regarded as secure with a 32 byte output.

use blake3;

/// # Blake3 Hasher
/// 
/// The BLAKE3 Hasher is a collision-resistant, efficient, and fast hashing algorithm designed to target 32 bytes in size while still maintaining speed and security.
pub struct Blake3Hasher;

impl Blake3Hasher {
    /// Init a New Instance
    pub fn new() -> Self {
        Self
    }
    /// Hash the input
    pub fn update<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let hash = blake3::hash(data.as_ref());
        hash.as_bytes().to_vec()
    }
}