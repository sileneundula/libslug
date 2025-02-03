use bip39::Language;
use ed25519_dalek::{Signer,Verifier};
use ed25519_dalek::ed25519::SignatureEncoding;
use ed25519_dalek::SignatureError;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::Signature;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};
use crate::slugcrypt::internals::bip39::SlugMnemonic;
use crate::slugcrypt::internals::csprng::SlugCSPRNG;
use crate::errors::SlugErrors;
use subtle_encoding::hex;
use subtle_encoding::Error;

use bip39::ErrorKind;

use base32;
use base58::{FromBase58,ToBase58,FromBase58Error};
use serde_big_array::BigArray;


/// ED25519 Public Key (Verifying Key)
/// 
/// 32-byte Key in ED25519
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519PublicKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519SecretKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Debug,Serialize,Deserialize)]
pub struct ED25519Signature(#[serde(with = "BigArray")][u8;64]);

impl ED25519SecretKey {
    pub fn generate() -> ED25519SecretKey {
        let csprng = SlugCSPRNG::os_rand();
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes())
    }
    pub fn from_bip39(mnemonic: SlugMnemonic, language: bip39::Language, password: &str) -> Result<Vec<u8>,ErrorKind> {
        let seed = mnemonic.to_seed(password, language)?;
        Ok(seed)
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// [Encoding] UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// [Encoding] Decode From UPPER-HEXADECIMAL
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<ED25519SecretKey, SlugErrors> {
        let mut secret_key_array: [u8;32] = [0u8;32];
        
        if bytes.len() == 32 {
            secret_key_array.copy_from_slice(bytes);
            return Ok(ED25519SecretKey(secret_key_array))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    fn to_usable_type(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
    pub fn public_key(&self) -> Result<ED25519PublicKey,SignatureError> {
        let vk = self.to_usable_type().verifying_key();
        Ok(ED25519PublicKey(vk.to_bytes()))
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<ED25519Signature,SignatureError> {
        let signature = self.to_usable_type().try_sign(msg.as_ref())?;


        return Ok(ED25519Signature(signature.to_bytes()))
    }
}

impl ED25519PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    pub fn from_bytes(bytes: [u8;32]) -> Self {
        Self(bytes)
    }
    pub fn to_usable_type(&self) -> Result<VerifyingKey,SignatureError> {
        VerifyingKey::from_bytes(&self.0)
    }
    pub fn verify<T: AsRef<[u8]>>(&self, signature: ED25519Signature, msg: T) -> Result<bool,SignatureError> {
        let x = self.to_usable_type().unwrap().verify_strict(msg.as_ref(), &signature.to_usable_type())?;
        return Ok(true)
    }
    /// [Encoding] Encode From UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// [Encoding] Decode From UPPER-HEXADECIMAL
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
    pub fn to_base32_string(&self) -> String {
        base32::encode(base32::Alphabet::Crockford, &self.0)
    }
    pub fn from_base32_string<T: AsRef<str>>(bs32_str: T) -> Vec<u8> {
        let bytes = base32::decode(base32::Alphabet::Crockford, bs32_str.as_ref()).unwrap();
        return bytes
    }
}

impl ED25519Signature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8;64] {
        self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut signature_array: [u8;64] = [0u8;64];
        
        if bytes.len() == 64 {
            signature_array.copy_from_slice(bytes);
            return Ok(Self(signature_array))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    fn to_usable_type(&self) -> Signature {
        Signature::from_bytes(&self.0)
    }
    pub fn to_base58_string(&self) -> String {
        self.0.to_base58()
    }
    pub fn from_base58_string<T: AsRef<str>>(base58_str: T) -> Result<Vec<u8>,FromBase58Error> {
        let bytes = base58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
    /// [Encoding] Encode From UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// [Encoding] Decode From UPPER-HEXADECIMAL
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
}


#[test]
fn run() {
    let sk = ED25519SecretKey::generate();
    println!("Secret Key: {:?}", sk);
}