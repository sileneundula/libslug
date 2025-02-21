use subtle_encoding::hex;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct SlugDigest(String);

impl SlugDigest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::string::FromUtf8Error> {
        let hex_bytes = hex::encode_upper(bytes);
        let digest = String::from_utf8(hex_bytes)?;
        Ok(Self(digest))
    }
    pub fn digest(&self) -> &str {
        &self.0
    }
    pub fn to_string(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.0.clone())
    }
}