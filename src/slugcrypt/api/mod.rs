pub struct SlugCrypt;
pub struct SlugAsyCrypt;

/// Digests API (BLAKE2, SHA2, SHA3)
pub struct SlugDigest;

pub struct SlugCSPRNGAPI;

use bip39::{ErrorKind, Language};

use crate::slugcrypt::internals::encrypt::chacha20::*;
use crate::slugcrypt::internals::encrypt::aes256::{EncryptAES256, DecryptAES256};
use crate::slugcrypt::internals::encrypt::aes256;
use crate::slugcrypt::internals::encryption::ecies::*;

use crate::slugcrypt::internals::digest::blake2;
use crate::slugcrypt::internals::digest::sha2;
use crate::slugcrypt::internals::digest::sha3;
use crate::slugcrypt::internals::digest::digest;

use crate::slugcrypt::internals::csprng::SlugCSPRNG;

use crate::slugcrypt::internals::bip39::SlugMnemonic;

use super::internals::ciphertext::CipherText;

impl SlugCrypt {
    /// Encrypt Using XChaCha20Poly1305
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),chacha20poly1305::aead::Error> {
        let x = SlugEncrypt::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    /// Decrypt Using XChaCha20Poly1305
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

impl SlugAsyCrypt {
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, data: T) -> Result<super::internals::ciphertext::CipherText, ecies_ed25519::Error> {
        let ct: Result<super::internals::ciphertext::CipherText, ecies_ed25519::Error> = ECIESEncrypt::encrypt(pk, data.as_ref());
        return ct
    }
    pub fn decrypt(sk: ECSecretKey, ct: CipherText) -> Result<super::internals::messages::Message, ecies_ed25519::Error> {
        let x: Result<super::internals::messages::Message, ecies_ed25519::Error> = ECIESDecrypt::decrypt(sk, ct);
        return x
    }
}

impl SlugCSPRNGAPI {
    pub fn new(pass: &str) -> [u8;32] {
        SlugCSPRNG::new(pass)
    }
    pub fn from_os() -> [u8;32] {
        SlugCSPRNG::os_rand()
    }
    pub fn mnemonic(mnemonic: SlugMnemonic, pass: &str, language: Language) -> Result<[u8;32],ErrorKind> {
        let seed = mnemonic.to_seed(pass, language)?;
        let mut output: [u8;32] = [0u8;32];

        output.copy_from_slice(&seed);

        Ok(output)
    }
}
