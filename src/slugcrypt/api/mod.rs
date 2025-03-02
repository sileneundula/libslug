pub struct SlugCrypt;
pub struct SlugAsyCrypt;

/// Digests API (BLAKE2, SHA2, SHA3)
pub struct SlugDigest;

use crate::slugcrypt::internals::encrypt::chacha20::*;
use crate::slugcrypt::internals::encrypt::aes256::{EncryptAES256, DecryptAES256};
use crate::slugcrypt::internals::encrypt::aes256;

use crate::slugcrypt::internals::digest::blake2;
use crate::slugcrypt::internals::digest::sha2;
use crate::slugcrypt::internals::digest::sha3;
use crate::slugcrypt::internals::digest::digest;

impl SlugCrypt {
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),chacha20poly1305::aead::Error> {
        let x = SlugEncrypt::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, data: EncryptionCipherText) -> Result<Vec<u8>,chacha20poly1305::aead::Error> {
        let x = SlugEncrypt::decrypt(key, nonce, data)?;
        return Ok(x)
    }
    pub fn encrypt_aes256<T: AsRef<[u8]>>(key: aes256::EncryptionKey, data: T) -> Result<(aes256::AESCipherText,aes256::EncryptionNonce),aes_gcm::Error> {
        let x: (aes256::AESCipherText, aes256::EncryptionNonce) = EncryptAES256::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    pub fn decrypt_aes256(key: aes256::EncryptionKey, nonce: aes256::EncryptionNonce, data: aes256::AESCipherText) -> Result<Vec<u8>,aes_gcm::Error> {
        let x = DecryptAES256::decrypt(key, nonce, data)?;
        return Ok(x)
    }
}

impl SlugDigest {
    pub fn blake2b(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = blake2::SlugBlake2bHasher::new(size);
        let result = hasher.hash(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    pub fn blake2s(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = blake2::SlugBlake2sHasher::new(size);
        let result = hasher.hash(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    pub fn sha2(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = sha2::Sha2Hasher::new(size);
        let result = hasher.hash(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    pub fn sha3(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = sha3::Sha3Hasher::new(size);
        let result = hasher.digest(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
}

