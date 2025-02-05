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
pub struct ECIESEncrypt;
pub struct ECIESDecrypt;

#[derive(Clone,Serialize,Deserialize)]
pub struct ECPublicKey {
    pub public_key: PublicKey,
}

#[derive(Serialize,Deserialize)]
pub struct ECSecretKey {
    pub secret_key: SecretKey,
}

impl ECIESEncrypt {
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, msg: T) -> Result<CipherText,Error>  {
        let mut csprng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut csprng)?;

        return Ok(CipherText::from_bytes(&ciphertext))
    }
}

impl ECIESDecrypt {
    pub fn decrypt(sk: ECSecretKey, ciphertext: CipherText) -> Result<Message,Error> {
        let decoded_msg = ecies_ed25519::decrypt(&sk.secret_key, ciphertext.as_bytes())?;

        Ok(Message::new(decoded_msg))
    }
}

impl ECPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.public_key.to_bytes()
    }
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let public_key = ecies_ed25519::PublicKey::from_bytes(&bytes)?;

        return Ok(Self {
            public_key
        })
    }
    pub fn to_hex_string(&self) -> Result<String,FromUtf8Error> {
        let bytes = hex::encode_upper(self.public_key.as_bytes());
        Ok(String::from_utf8(bytes)?)
    }
    pub fn from_hex_string<T: AsRef<str>>(bytes: T) -> Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(bytes.as_ref().as_bytes())?)
    }
    pub fn to_base58_string(&self) -> String {
        self.public_key.as_bytes().to_base58()
    }
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
    pub fn to_bytes(&self) -> [u8;32] {
        self.secret_key.to_bytes()
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let secret_key = ecies_ed25519::SecretKey::from_bytes(&bytes)?;
        
        return Ok(Self {
            secret_key
        })
    }
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
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, msg: T) -> Result<CipherText,Error> {
        let mut rng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut rng)?;

        return Ok(CipherText::from_bytes(&ciphertext))
    }
    pub fn decrypt(self, ciphertext: CipherText) -> Result<Message,Error> {
        ECIESDecrypt::decrypt(self, ciphertext)
    }
    pub fn to_hex_string(&self) -> Result<String,FromUtf8Error> {
        let bytes = hex::encode_upper(self.secret_key.as_bytes());
        Ok(String::from_utf8(bytes)?)
    }
    pub fn from_hex_string<T: AsRef<str>>(bytes: T) -> Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(bytes.as_ref().as_bytes())?)
    }
}
