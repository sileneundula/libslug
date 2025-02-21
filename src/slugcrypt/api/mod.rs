pub struct SlugCrypt;

use crate::slugcrypt::internals::encrypt::chacha20::*;

impl SlugCrypt {
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),chacha20poly1305::aead::Error> {
        let x = SlugEncrypt::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, data: EncryptionCipherText) -> Result<Vec<u8>,chacha20poly1305::aead::Error> {
        let x = SlugEncrypt::decrypt(key, nonce, data)?;
        return Ok(x)
    }
}

