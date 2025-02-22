

#[derive(Clone,Debug,Zeroize,ZeroizeOnDrop)]
pub struct EncryptionKey([u8;32]);

#[derive(Clone, Debug,Zeroize,ZeroizeOnDrop)]
pub struct EncryptionNonce([u8;12]);

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};


use hybrid_array::Array;
use schnorrkel::derive;
use subtle_encoding::hex;
use base58::{FromBase58,ToBase58,FromBase58Error};
use zeroize::{Zeroize,ZeroizeOnDrop};

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode(self.as_bytes());
        String::from_utf8(bytes)
    }
    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Self(key)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Self(key)
    }
    pub fn securerandgenerate(pass: &str) -> [u8;32] {
        let rng = securerand_rs::securerand::SecureRandom::new(pass);
        return rng
    }
    pub fn generate() -> Self {
        let key: [u8;32] = crate::slugcrypt::internals::csprng::SlugCSPRNG::os_rand();
        return Self(key)
    }
}

impl EncryptionNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode(self.as_bytes());
        String::from_utf8(bytes)
    }
    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes);
        Self(nonce)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(bytes);
        Self(nonce)
    }
}

pub struct EncryptAES256;
pub struct DecryptAES256;

pub struct AESCipherText {
    pub ciphertext: Vec<u8>,
}

impl AESCipherText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn bs58(&self) -> String {
        self.ciphertext.to_base58()
    }
    pub fn from_bs58(s: &str) -> Result<Self,FromBase58Error> {
        let bs58 = s.from_base58()?;

        return Ok(Self {
            ciphertext: bs58
        })
    }
}

impl EncryptAES256 {
    pub fn encrypt<T: AsRef<[u8]>>(key_s: EncryptionKey, data: T) -> Result<(AESCipherText,EncryptionNonce), aes_gcm::Error> {
        // Key Array
        let key_array: [u8; 32] = key_s.as_bytes().try_into().unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data.as_ref())?;
        
        Ok(
            (
                AESCipherText {ciphertext} , EncryptionNonce::from_bytes(nonce.as_slice())
            )
        )
    }
}

impl DecryptAES256 {
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, data: AESCipherText) -> Result<Vec<u8>, aes_gcm::Error> {
        // Key Array
        let key_array: [u8; 32] = key.as_bytes().try_into().unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce.as_bytes());
        let plaintext = cipher.decrypt(nonce, data.as_bytes())?;
        
        Ok(plaintext)
    }
}