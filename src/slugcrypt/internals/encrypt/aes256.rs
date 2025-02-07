pub struct EncryptionKey([u8;32]);

pub struct EncryptionNonce([u8;24]);

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

pub struct EncryptAES256;
pub struct DecryptAES256;

impl EncryptionKey {
    pub fn generate() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let key: [u8;32] = key.as_slice().try_into().unwrap();
        return Self(key)
    }
}