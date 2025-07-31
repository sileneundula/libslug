//! # ECIES-ED25519-silene
//! 
//! ECIES is an elliptic curve public key encryption algorithm that can be used to encrypt data using public keys that can only be decrypted by the private key.
//! 
//! In this library, we use `ecies-ed25519-silene`, a fork of another library using ECIES with Curve25519 and the SHA3 hash function (as opposed to SHA2).
//! 
//! It implements zeroize for security for the secret key.
//! 
//! ## TODO
//! 
//! - Fix `Message`

use std::string::FromUtf8Error;

/// # ECIES over Curve25519 (Encryption)
/// 
/// This module contains the required data to implement ECIES over Curve25519. This is the standard method of encryption.

use ecies_ed25519::PublicKey;
use ecies_ed25519::SecretKey;
use ecies_ed25519::Error;

// SlugCrypt Structs
use crate::slugcrypt::internals::ciphertext::CipherText;
use crate::slugcrypt::internals::messages::Message;

use serde::{Serialize,Deserialize};
use subtle_encoding::hex;
use base58::{FromBase58,ToBase58,FromBase58Error};

//use rand::RngCore;
use rand::rngs::OsRng;
//use rand::CryptoRng;


/// # ECIES Encrypt
/// 
/// ECIESEncrypt is the encryption struct for encrypting data using Curve25519
pub struct ECIESEncrypt;

/// # ECIES Decrypt
/// 
/// ECIESDecrypt is the decryption struct for decrypting data using Curve25519
pub struct ECIESDecrypt;

/// # ECPublicKey (ECIES-ED25519 Public Key For Encryption/Decryption)
/// 
/// This provides us with the interface for using ECIES with ED25519 with zeroize implemented to encrypt/decrypt data.
/// 
/// ## Features
/// 
/// - To and From Bytes
/// - To and From Hexadecimal
/// - To and From Base58
#[derive(Clone,Serialize,Deserialize)]
pub struct ECPublicKey {
    pub public_key: PublicKey,
}

/// # ECSecretKey (ECIES-ED25519 Public Key For Encryption/Decryption)
/// 
/// This provides us with the interface for using ECIES with ED25519 with zeroize implemented to encrypt/decrypt data. It does not implement clone.
/// 
/// ## Features
/// 
/// ### Generation
/// 
/// - Generate from operating system randomness
/// 
/// ### Conversion
/// 
/// - To and From Bytes
/// - To and From Hex (Upper)
/// 
/// ### Encryption
/// 
/// - Encrypt
/// - Decrypt
/// - Get Public Key

#[derive(Serialize,Deserialize)]
pub struct ECSecretKey {
    pub secret_key: SecretKey,
}

impl ECIESEncrypt {
    /// # Encrypt (ECIES-ED25519-Silene)
    /// 
    /// ## Description
    /// 
    /// Encryption via a public key and a message.
    /// 
    /// **Randomness:** Uses operating system randomness to encrypt.
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, msg: T) -> Result<CipherText,Error>  {
        let mut csprng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut csprng)?;

        return Ok(CipherText::from_bytes(&ciphertext))
    }
}

impl ECIESDecrypt {
    /// # Decrypt (ECIES-ED25519-Silene)
    /// 
    /// ## Description
    /// 
    /// Decryption via a secret key and a ciphertext. Decodes to `Message` struct, a vec.
    pub fn decrypt(sk: ECSecretKey, ciphertext: CipherText) -> Result<Message,Error> {
        let decoded_msg = ecies_ed25519::decrypt(&sk.secret_key, ciphertext.as_bytes())?;

        Ok(Message::new(decoded_msg))
    }
}

impl ECPublicKey {
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }
    /// to byte array of 32 bytes
    pub fn to_bytes(&self) -> [u8;32] {
        self.public_key.to_bytes()
    }
    /// from byte array of 32 bytes
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let public_key = ecies_ed25519::PublicKey::from_bytes(&bytes)?;

        return Ok(Self {
            public_key
        })
    }
    /// to hex string (constant-time) (upper)
    pub fn to_hex_string(&self) -> Result<String,FromUtf8Error> {
        let bytes = hex::encode_upper(self.public_key.as_bytes());
        Ok(String::from_utf8(bytes)?)
    }
    /// from hex string (constant-time) (upper)
    pub fn from_hex_string<T: AsRef<str>>(bytes: T) -> Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(bytes.as_ref().as_bytes())?)
    }
    /// to base58
    pub fn to_base58_string(&self) -> String {
        self.public_key.as_bytes().to_base58()
    }
    /// from base58
    pub fn from_base58_string<T: AsRef<str>>(bs58_str: T) -> Result<Vec<u8>,FromBase58Error> {
        Ok(bs58_str.as_ref().from_base58())?
    }
}

impl ECSecretKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;

        let secret_key = ecies_ed25519::SecretKey::generate(&mut rng);

        ECSecretKey {
            secret_key
        }
    }
    /// to bytes (32-byte array)
    pub fn to_bytes(&self) -> [u8;32] {
        self.secret_key.to_bytes()
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }
    /// from bytes (32-byte array)
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let secret_key = ecies_ed25519::SecretKey::from_bytes(&bytes)?;
        
        return Ok(Self {
            secret_key
        })
    }
    /// from byte slice
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self,Error> {
        let secret_key = ecies_ed25519::SecretKey::from_bytes(bytes)?;

        return Ok(Self {
            secret_key
        })
    }
    /// Converts ECIES-Curve25519 Secret Key To Public Key
    pub fn public_key(&self) -> ECPublicKey {
        let public_key = ecies_ed25519::PublicKey::from_secret(&self.secret_key);

        ECPublicKey {
            public_key
        }
    }
    /// Encrypt message using ECIES-ED25519
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, msg: T) -> Result<CipherText,Error> {
        let mut rng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut rng)?;

        return Ok(CipherText::from_bytes(&ciphertext))
    }
    /// Decrypt message using ECIES-ED25519 returning a Message struct
    pub fn decrypt(self, ciphertext: CipherText) -> Result<Message,Error> {
        ECIESDecrypt::decrypt(self, ciphertext)
    }
    /// To Hex String (Upper)
    pub fn to_hex_string(&self) -> Result<String,FromUtf8Error> {
        let bytes = hex::encode_upper(self.secret_key.as_bytes());
        Ok(String::from_utf8(bytes)?)
    }
    /// From Hex String (Upper)
    pub fn from_hex_string<T: AsRef<str>>(bytes: T) -> Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(bytes.as_ref().as_bytes())?)
    }
}
