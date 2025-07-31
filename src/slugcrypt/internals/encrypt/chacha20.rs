//! # XChaCha20-Poly1305 (Extended Nonce) (also known as ChaCha20 or Salsa but the extended nonce version)
//! 
//! This symmetric encryption cipher is a stream cipher and encrypts data differently than AES256-GCM. As opposed to blocks, it uses a stream.
//! 
//! It is widely regarded as secure and used in many applications.
//! 
//! ## Contents
//! 
//! 1. `EncryptionKey`: 32-byte encryption key, implements zeroize
//! 2. `EncryptionNonce`: 24-byte encryption nonce, implements zeroize
//! 3. `EncryptionCipherText`: ChaCha20-Poly1305 Encryption Ciphertext as a vector of bytes

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

/// # XChaCha20-Poly1305 EncryptionKey
/// 
/// ## Description
/// 
/// 32-byte encryption key that implements zeroize.
/// 
/// ## Features
/// 
/// ### Generation
/// 
/// - Generate From Operating System Randomness
/// - Generate Using SecureRand and Ephermal Passwords (ChaCha20RNG + Argon2id + OSCSPRNG)
/// - Generate Using Deterministic Approach (Password + Salt)
/// 
/// ### Conversion
/// - To Hexadecimal (Upper) (Constant-Time)
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct EncryptionKey {
    pub key: [u8; 32]
}

/// # XChaCha20-Poly1305 EncryptionNonce
/// 
/// ## Description
/// 
/// 24-byte encryption key that implements zeroize.
/// 
/// ## Features
/// 
/// ### Conversion
/// - To and From Bytes
/// - To and From Hexadecimal (Upper) (Constant-Time)
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct EncryptionNonce {
    pub nonce: [u8;24]
}

/// # XChaCha20-Poly1305 EncryptionCipherText
/// 
/// **Note:** XChaCha20-Poly1305 Only, Not AES256-GCM
/// 
/// ## Description
/// 
/// A vector of bytes that include the data to be decrypted by XChaCha20-Poly1305.
/// 
/// ## Features
/// 
/// ### Conversion
/// 
/// - To and From Bytes
/// - To and From Base58 (Not Constant-Time)
/// - To and From Hexadecimal (Constant-Time)
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct EncryptionCipherText {
    pub ciphertext: Vec<u8>,
}

impl EncryptionCipherText {
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
    /// To Bytes (uses clone)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// To Base58
    pub fn bs58(&self) -> String {
        self.ciphertext.to_base58()
    }
    /// From Base58
    pub fn from_bs58(s: &str) -> Result<Self,FromBase58Error> {
        let bs58 = s.from_base58()?;

        return Ok(Self {
            ciphertext: bs58
        })
    }
    /// To Hex (Upper) (Constant-Time)
    pub fn to_hex(&self) -> Result<String,FromUtf8Error> {
        let bytes = subtle_encoding::hex::encode_upper(&self.ciphertext);
        let hex_key = String::from_utf8(bytes)?;
        return Ok(hex_key)
    }
    /// From Hex (Upper) (Constant-Time)
    pub fn from_hex(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let ciphertext = subtle_encoding::hex::decode_upper(hex_str)?;

        return Ok(Self {
            ciphertext: ciphertext
        })
    }
}

impl EncryptionNonce {
    /// As Bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.nonce
    }
    /// To vec
    pub fn to_vec(&self) -> Vec<u8> {
        self.nonce.to_vec()
    }
    /// To Bytes (array of 24 bytes)
    pub fn to_bytes(&self) -> [u8;24] {
        self.nonce
    }
    /// To Hexadecimal
    pub fn to_hex(&self) -> Result<String,FromUtf8Error> {
        let bytes = subtle_encoding::hex::encode_upper(self.nonce);
        let hex_key = String::from_utf8(bytes)?;
        return Ok(hex_key)
    }
    /// From Upper Hexadecimal (Constant-Time)
    pub fn from_hex(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let nonce = subtle_encoding::hex::decode_upper(hex_str)?;

        let nonce_array: [u8;24] = nonce.try_into().unwrap();

        return Ok(Self {
            nonce: nonce_array,
        })
    }
    /// From Array of Bytes
    pub fn from_bytes(bytes: [u8;24]) -> Self {
        return Self {
            nonce: bytes
        }
    }
}

impl EncryptionKey {
    /// # XChaCha20-Poly1305 (Operating System Randomness Generation)
    /// 
    /// Generate XChaCha20-Poly1305 Encryption Key Using Operating System Randomness
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut key: [u8;32] = [0u8;32];

        rng.fill_bytes(&mut key);

        return Self {
            key: key,
        }
    }
    /// # XChaCha20-Poly1305 (SecureRand Generation Using Ephermal Passwords)
    /// 
    /// Generate XChaCha20-Poly1305 Encryption Key Using SecureRand Generation (Ephermal Passwords with OSRNG + ChaCha20RNG + Argon2id)
    pub fn generate_securerand(pass: &str) -> Self {
        let x = SlugCSPRNG::new(pass);

        return Self {
            key: x,
        }
    }
    /// # \[Deterministic Generation] Generate XChaCha20-Poly1305 Encryption Key Determinstically Using SecureRand Password + Salt
    /// 
    /// Both the password and salt must be remembered to get the key again.
    /// 
    /// It is advisable to use a CSPRNG for the salt and to save the salt.
    pub fn generate_deterministic(pass: &str, salt: &str) -> Self {
        let x = SlugCSPRNG::derive_from_password_with_salt(pass, salt);

        return Self {
            key: x
        }
    }
    /// To Hexadecimal
    pub fn to_hex(&self) -> Result<String,FromUtf8Error> {
        let bytes = subtle_encoding::hex::encode_upper(self.key);
        let hex_key = String::from_utf8(bytes)?;
        return Ok(hex_key)
    }
    /// As Array
    pub fn as_array(&self) -> [u8;32] {
        self.key
    }
    /// As Bytes
    pub fn as_bytes(&self) -> &[u8] {
        return &self.key
    }
    /// From Hexadecimal (Upper)
    pub fn from_hex(hex_str: &str) -> Result<Self,subtle_encoding::Error> {
        let key = subtle_encoding::hex::decode_upper(hex_str)?;

        let key_array: [u8;32] = key.try_into().unwrap();

        return Ok(Self {
            key: key_array,
        })
    }
}

/// # XChaCha20Encrypt (Encryption and Decryption)
/// 
/// **Creator:** Designed by Scott Arciszewski as an extension to djb's work
/// 
/// ## Description
/// 
/// The main usage of `XChaCha20Encrypt` is to use the algorithm XChaCha20-Poly1305 to encrypt/decrypt data, generating and returning the nonce/ciphertext or taking as input the needed types for decryption.
/// 
/// The nonce is generated by using operating system cryptographic randomness.
/// 
/// ## Contents
/// 
/// 1. `EncryptionKey`: 32-bytes
/// 2. `EncryptionNonce`: 24-bytes (generated by Operating System on function call)
/// 3. `EncryptionCipherText`: A vector of bytes to be decrypted by the `EncryptionKey` and `EncryptionNonce`
pub struct XChaCha20Encrypt;

impl XChaCha20Encrypt {
    /// Encrypt using XChaCha20-Poly1305
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
    /// Decrypt Using XChaCha20-Poly1305
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, ciphertext: EncryptionCipherText) -> Result<Vec<u8>,chacha20poly1305::Error> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let decrypted = cipher.decrypt(XNonce::from_slice(&nonce.as_bytes()),ciphertext.as_bytes())?;

        return Ok(decrypted)
    }
}