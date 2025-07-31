//! # Digest
//! 
//! This allows for usage of digests of Hash Functions while maintaing some security considerations like zeroize and constant-time encoding.

use subtle_encoding::hex;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};

/// # SlugDigest
/// 
/// SlugDigest lets you convert bytes into hexadecimal (upper) using zeroize and constant-time encoding.
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct SlugDigest(String);

impl SlugDigest {
    /// Convert from bytes to hex string
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::string::FromUtf8Error> {
        let hex_bytes = hex::encode_upper(bytes);
        let digest = String::from_utf8(hex_bytes)?;
        Ok(Self(digest))
    }
    /// Return as a string
    pub fn digest(&self) -> &str {
        &self.0
    }
    /// To Zeroized String
    pub fn to_string(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.0.clone())
    }
}