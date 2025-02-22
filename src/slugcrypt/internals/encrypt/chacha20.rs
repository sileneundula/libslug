use std::str::Utf8Error;
use base58::{FromBase58,ToBase58,FromBase58Error};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng}, XNonce, AeadCore, Error, Key, Nonce, XChaCha20Poly1305 // Cipher, key, and nonce types
};

use std::string::FromUtf8Error;
use rand::CryptoRng;
use rand::RngCore;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};

use subtle_encoding::hex;
use crate::slugcrypt::internals::csprng::SlugCSPRNG;

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct EncryptionKey {
    key: [u8; 32]
}

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct EncryptionNonce {
    nonce: [u8;24]
}

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct EncryptionCipherText {
    ciphertext: Vec<u8>,
}

impl EncryptionCipherText {
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

impl EncryptionNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.nonce
    }
    pub fn to_hex(&self) -> Result<String,FromUtf8Error> {
        let bytes = subtle_encoding::hex::encode_upper(self.nonce);
        let hex_key = String::from_utf8(bytes)?;
        return Ok(hex_key)
    }
    pub fn from_hex(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let nonce = subtle_encoding::hex::decode_upper(hex_str)?;

        let nonce_array: [u8;24] = nonce.try_into().unwrap();

        return Ok(Self {
            nonce: nonce_array,
        })
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
    pub fn securerandgenerate(pass: &str) -> Self {
        let x = SlugCSPRNG::new(pass);

        return Self {
            key: x,
        }
    }
    pub fn to_hex(&self) -> Result<String,FromUtf8Error> {
        let bytes = subtle_encoding::hex::encode_upper(self.key);
        let hex_key = String::from_utf8(bytes)?;
        return Ok(hex_key)
    }
    pub fn as_array(&self) -> [u8;32] {
        self.key
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.key
    }
    pub fn from_hex(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let key = subtle_encoding::hex::decode_upper(hex_str)?;

        let key_array: [u8;32] = key.try_into().unwrap();

        return Ok(Self {
            key: key_array,
        })
    }
}

pub struct SlugEncrypt;

impl SlugEncrypt {
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),Error> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));

        //let mut nonce_array: [u8;24] = [0u8;24];

        // Nonce_Vec
        let nonce_vec = nonce.as_slice().to_vec();

        // Nonce Array (passed to Self)
        let nonce_array: [u8;24] = nonce_vec.try_into().unwrap();
        

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
        let decrypted = cipher.decrypt(XNonce::from_slice(&nonce.as_bytes()),ciphertext.as_bytes())?;

        return Ok(decrypted)
    }
}