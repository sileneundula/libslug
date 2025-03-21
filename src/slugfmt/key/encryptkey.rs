use crate::slugcrypt::internals::encrypt::aes256;
use crate::slugcrypt::internals::encrypt::chacha20;
use serde::{Serialize,Deserialize};
use crate::slugcrypt::internals::digest::blake2::SlugBlake2sHasher;
use crate::slugcrypt::internals::digest::digest::SlugDigest;


/// .sctx - Slug Cipher Text
/// .skey - Slug Key Text

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
            platform: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::AES256GCM,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).hash(key.to_hex().unwrap().as_bytes())).unwrap().to_string().as_str().to_string()
        };
        key
    }
    pub fn xchacha20(key: chacha20::EncryptionKey, nonce: chacha20::EncryptionNonce) -> Self {
        let key = SlugEncryptKey {
            version: 0u8,
            platform: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::XChaCha20Poly1305,
            key: key.to_hex().unwrap(),
            nonce: nonce.to_hex().unwrap(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).hash(key.to_hex().unwrap().as_bytes())).unwrap().to_string().as_str().to_string()
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

        let message = chacha20::SlugEncrypt::decrypt(key, nonce, ciphertext).unwrap();
        return message;
    }
}

impl SlugCipherText {
    pub fn aes256(name: String, ciphertext: aes256::AESCipherText) -> Self {
        let ct = SlugCipherText {
            version: 0u8,
            platform: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::AES256GCM,
            common_name: name,
            ciphertext: ciphertext.bs58(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).hash(ciphertext.bs58().as_bytes())).unwrap().to_string().as_str().to_string()

        };
        return ct
    }
    pub fn xchacha20(name: String, ciphertext: chacha20::EncryptionCipherText) -> Self {
        let ct = SlugCipherText {
            version: 0u8,
            platform: "SLUGCRYPT".to_string(),
            alg: SlugEncryptAlgorithm::XChaCha20Poly1305,
            common_name: name,
            ciphertext: ciphertext.bs58(),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(8).hash(ciphertext.bs58().as_bytes())).unwrap().to_string().as_str().to_string()
        };
        return ct
    }
}

impl SlugDecryptedOutput {
    pub fn new(output: Vec<u8>) -> Self {
        SlugDecryptedOutput {
            version: 0u8,
            platform: String::from("SLUGCRYPT"),
            fingerprint: SlugDigest::from_bytes(&SlugBlake2sHasher::new(6).hash(&output)).unwrap().to_string().as_str().to_string(),
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