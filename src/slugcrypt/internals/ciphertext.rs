use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use base58::{FromBase58,ToBase58};
use subtle_encoding::hex;
use subtle_encoding::base64;

use slugencode::SlugEncodingUsage;
use slugencode::SlugEncodings;
use slugencode::errors::SlugEncodingError;

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CipherText {
    pub ciphertext: Vec<u8>,
}

impl CipherText {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            ciphertext: bytes,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            ciphertext: bytes.to_vec()
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    pub fn to_hex(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base58(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> Result<String, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        Ok(Self {
            ciphertext: output
        })
    }
    pub fn to_bs58(&self) -> String {
        self.ciphertext.to_base58()
    }
    pub fn from_bs58(bs58: &str) -> Result<Self, base58::FromBase58Error> {
        let ciphertext = bs58.from_base58()?;
        Ok(Self {
            ciphertext: ciphertext,
        })
    }
    pub fn to_hex_upper_ct(&self) -> Vec<u8> {
        return hex::encode_upper(&self.ciphertext)
    }
    pub fn from_hex_upper_ct(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let bytes = hex::decode_upper(hex_str)?;

        Ok(Self {
            ciphertext: bytes,
        })
    }
    pub fn to_base64_ct(&self) -> Vec<u8> {
        base64::encode(&self.ciphertext)
    }
    pub fn from_base64_ct(bytes: &[u8]) -> Result<Vec<u8>, subtle_encoding::Error> {
        base64::decode(bytes)
    }
}