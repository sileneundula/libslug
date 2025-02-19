pub struct EncryptionKey([u8;32]);

pub struct EncryptionNonce([u8;24]);

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

/*
use hybrid_array::Array;

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct EncryptAES256;
pub struct DecryptAES256;

impl EncryptionKey {
    pub fn generate() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let key: [u8;32] = key.as_slice().try_into().unwrap();
        return Self(key)
    }
}

impl EncryptAES256 {
    pub fn encrypt<T: AsRef<[u8]>>(key_s: EncryptionKey, data: T) {
        let key = Key::from_slice(Array::from_slice(key_s.as_bytes()));
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    }
}
    */