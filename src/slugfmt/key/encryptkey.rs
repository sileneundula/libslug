use crate::slugcrypt::internals::encrypt::aes256;
use crate::slugcrypt::internals::encrypt::chacha20;
use serde::{Serialize,Deserialize};

#[derive(Serialize,Deserialize,Debug,Clone,Copy)]
pub struct SlugEncryptKey {
    pub version: u8,
    pub version_type: String,
    pub alg: SlugEncryptAlgorithm,
    
    pub key: String,
    pub nonce: String,
}

impl SlugEncryptKey {
    pub fn aes256(key: aes256::EncryptionKey, nonce: aes256::EncryptionNonce) -> Self {
        let key = SlugEncryptKey {
            version: 0u8,
            version_type: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::AES256GCM,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
        };
        key
    }
    pub fn xchacha20(key: chacha20::EncryptionKey, nonce: chacha20::EncryptionNonce) -> Self {
        let key = SlugEncryptKey {
            version: 0u8,
            version_type: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::XChaCha20Poly1305,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
        };
            return key
        }
    }


#[derive(Serialize,Deserialize,Debug,Clone,Copy)]
pub enum SlugEncryptAlgorithm {
    AES256GCM,
    XChaCha20Poly1305,
}