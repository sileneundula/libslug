pub struct SlugCrypt;

pub struct SlugAsyCrypt;

use crate::slugcrypt::internals::encrypt::chacha20::*;
use crate::slugcrypt::internals::encrypt::aes256::{EncryptAES256, DecryptAES256};
use crate::slugcrypt::internals::encrypt::aes256;

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

