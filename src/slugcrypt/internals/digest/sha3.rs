//! # SHA3
//! 
//! SHA3 is the finalizist of the NIST Competition using the Sponge-Function.
//! 
//! It comes in sizes of {224,256,384,512} and is generally regarded as highly secure.

use tiny_keccak::Sha3;
use tiny_keccak::Hasher;
use tiny_keccak::Xof;

/// # SHA3 Hasher
/// 
/// Initialize a SHA3 Hasher using {224,256,384,512}
pub struct Sha3Hasher(usize);

impl Sha3Hasher {
    /// Initialize the SHA3 Hasher with the given bits {224,256,384,512}
    /// 
    /// If an invalid value is added, it resorts to 512.
    pub fn new(bits: usize) -> Self {
        match bits {
            224 => Self(224),
            256 => Self(256),
            384 => Self(384),
            512 => Self(512),
            _ => Self(512),
        }
    }
    fn get_hasher(&self) -> Sha3 {
        match self.0 {
            224 => Sha3::v224(),
            256 => Sha3::v256(),
            384 => Sha3::v384(),
            512 => Sha3::v512(),
            _ => Sha3::v512()
        }
    }
    /// Hash the input
    pub fn update<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let mut hasher = self.get_hasher();
        hasher.update(data.as_ref());
        let mut output = vec![0u8; self.0 / 8];
        hasher.finalize(&mut output);
        output
    }
}