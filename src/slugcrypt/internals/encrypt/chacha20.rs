use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng}, AeadCore, Error, Key, Nonce, XChaCha20Poly1305 // Cipher, key, and nonce types
};

use rand::CryptoRng;
use rand::RngCore;
use zeroize::{Zeroize,ZeroizeOnDrop};

#[derive(Zeroize,ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: [u8; 32]
}

#[derive(Zeroize,ZeroizeOnDrop)]
pub struct EncryptionNonce {
    nonce: [u8;25]
}

#[derive(Zeroize,ZeroizeOnDrop)]
pub struct EncryptionCipherText {
    ciphertext: Vec<u8>,
}

impl EncryptionCipherText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl EncryptionNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.nonce
    }
    pub fn as_array(&self) -> [u8;25] {
        return self.nonce
    }
}

impl EncryptionKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut key: [u8;32] = [0u8;32];

        rng.fill_bytes(&mut key);

        return Self {
            key: key,
        }
    }
    pub fn to_hex(&self) -> Vec<u8> {
        subtle_encoding::hex::encode_upper(self.key)
    }
    pub fn as_array(&self) -> [u8;32] {
        self.key
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.key
    }
}

pub struct SlugEncrypt;

impl SlugEncrypt {
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),Error> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));

        let nonce_array: [u8;25] = nonce.as_slice().try_into().unwrap();
        

        let ciphertext = cipher.encrypt(&nonce, data.as_ref())?;

        return Ok(
            (EncryptionCipherText {
                ciphertext: ciphertext
            },
            EncryptionNonce {
                nonce: nonce_array
            })
        )
    }
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, ciphertext: EncryptionCipherText) -> Result<Vec<u8>,chacha20poly1305::Error> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let decrypted = cipher.decrypt(Nonce::from_slice(&nonce.as_array()),ciphertext.as_bytes())?;

        return Ok(decrypted)
    }
}