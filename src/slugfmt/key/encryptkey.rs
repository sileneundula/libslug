//! # Encryption Key
//! 
//! The "Slug Encryption Key Format (SEKF)" is used for AES256 and XCHACHA20-POLY1305 Symmetric Encryption. It includes the nonce and secret key.
//! 
//! It is a simple format serialized into YAML.
//! 
//! ## EncryptKey
//! 
//! Here is the following format for encrypt key:
//! 
//! 1. Version (u8)
//! 2. Platform
//!     a. Slug20 (default)
//!     b. Other
//! 3. Algorithm
//!     a. AES256GCM/XCHACHA20-POLY1305 (Slug20)
//!     b. Other added ones (Slug20)
//!     c. Any others
//! 4. Key (Vec<u8>)
//! 5. Nonce (Vec<u8>)
//! 6. Fingerprint (8 bytes - hex)

use crate::slugcrypt::internals::encrypt::aes256;
use crate::slugcrypt::internals::encrypt::chacha20;
use serde::{Serialize,Deserialize};
use crate::slugcrypt::internals::digest::blake2::SlugBlake2sHasher;
use crate::slugcrypt::internals::digest::digest::SlugDigest;

pub const PLATFORM: &str = "silene/slug20";


/// .sctx - Slug Cipher Text
/// .skey - Slug Key Text



/// # SlugEncryptKey
/// 
/// A `SlugEncryptKey` is used to decrypt data of a ciphertext. It is serialized in YAML.
#[derive(Serialize,Deserialize, PartialEq, Debug,Clone)]
pub struct SlugEncryptKey {
    pub version: u8,
    pub platform: String,
    pub alg: SlugEncryptAlgorithm,
    
    pub key: String,
    pub nonce: String,
    pub fingerprint: String,
}

#[derive(Serialize,Deserialize, PartialEq, Debug,Clone)]
pub struct SlugCipherText {
    pub version: u8,
    pub platform: String,
    pub alg: SlugEncryptAlgorithm,
    pub common_name: String,
    pub ciphertext: String,
    pub fingerprint: String,
}

pub struct SlugDecryptedOutput {
    pub version: u8,
    pub platform: String,
    pub output: Vec<u8>,
    pub fingerprint: String,
}

impl SlugEncryptKey {
    pub fn aes256(key: aes256::EncryptionKey, nonce: aes256::EncryptionNonce) -> Self {
        let key = SlugEncryptKey {
            version: 0u8,
            platform: PLATFORM.to_string(),
            alg: SlugEncryptAlgorithm::AES256GCM,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).update(key.to_hex().unwrap().as_bytes())).unwrap().to_string().as_str().to_string()
        };
        key
    }
    pub fn xchacha20(key: chacha20::EncryptionKey, nonce: chacha20::EncryptionNonce) -> Self {
        let key = SlugEncryptKey {
            version: 0u8,
            platform: PLATFORM.to_string(),
            alg: SlugEncryptAlgorithm::XChaCha20Poly1305,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).update(key.to_hex().unwrap().as_bytes())).unwrap().to_string().as_str().to_string()
        };
            return key
    }

    pub fn decrypt_aes256(&self, ciphertext: aes256::AESCipherText) -> Vec<u8> {
        if self.alg != SlugEncryptAlgorithm::AES256GCM {
            panic!("Invalid Algorithm");
        }
        let key = aes256::EncryptionKey::from_hex(&self.key);
        let nonce = aes256::EncryptionNonce::from_hex(&self.nonce);

        let message = aes256::DecryptAES256::decrypt(key, nonce, ciphertext).unwrap();
        return message;
    }
    pub fn decrypt_xchacha20(&self, ciphertext: chacha20::EncryptionCipherText) -> Vec<u8> {
        if self.alg != SlugEncryptAlgorithm::XChaCha20Poly1305 {
            panic!("Invalid Algorithm");
        }
        let key = chacha20::EncryptionKey::from_hex(&self.key).unwrap();
        let nonce = chacha20::EncryptionNonce::from_hex(&self.nonce).unwrap();

        let message = chacha20::XChaCha20Encrypt::decrypt(key, nonce, ciphertext).unwrap();
        return message;
    }
    pub fn unencrypted_serialize(&self) -> Result<String, serde_yaml::Error> {
        let yaml = serde_yaml::to_string(&self)?;
        Ok(yaml)
    }
    pub fn unencrypted_deserialize(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let x = serde_yaml::from_str(yaml)?;
        Ok(x)
    }
}

impl SlugCipherText {
    pub fn aes256(name: String, ciphertext: aes256::AESCipherText) -> Self {
        let ct = SlugCipherText {
            version: 0u8,
            platform: PLATFORM.to_string(),
            alg: SlugEncryptAlgorithm::AES256GCM,
            common_name: name,
            ciphertext: ciphertext.bs58(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).update(ciphertext.bs58().as_bytes())).unwrap().to_string().as_str().to_string()

        };
        return ct
    }
    pub fn xchacha20(name: String, ciphertext: chacha20::EncryptionCipherText) -> Self {
        let ct = SlugCipherText {
            version: 0u8,
            platform: PLATFORM.to_string(),
            alg: SlugEncryptAlgorithm::XChaCha20Poly1305,
            common_name: name,
            ciphertext: ciphertext.bs58(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).update(ciphertext.bs58().as_bytes())).unwrap().to_string().as_str().to_string()
        };
        return ct
    }
}

impl SlugDecryptedOutput {
    pub fn new(output: Vec<u8>) -> Self {
        SlugDecryptedOutput {
            version: 0u8,
            platform: String::from(PLATFORM),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(6).update(&output)).unwrap().to_string().as_str().to_string(),
            output: output,
        }
    }
    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn platform(&self) -> String {
        self.platform.clone()
    }
    pub fn output(&self) -> Vec<u8> {
        self.output.clone()
    }
    pub fn to_utf8(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.output.clone())
    }
}

#[derive(Serialize,Deserialize,PartialEq,Debug,Clone,Copy)]
pub enum SlugEncryptAlgorithm {
    AES256GCM,
    XChaCha20Poly1305,
}