use std::primitive;

use pqcrypto_sphincsplus::sphincsshake256ssimple::{PublicKey as PublicKeySphincs, SecretKey as SecretKeySphincs, DetachedSignature as DetachedSignatureSphincs};
use pqcrypto_sphincsplus::sphincsshake256ssimple::*;
use pqcrypto_traits::sign::VerificationError;
use pqcrypto_traits::{Error,Result,sign::{PublicKey,SecretKey,DetachedSignature,SignedMessage}};
use crate::errors::SlugErrors;
use crate::slugcrypt::internals::messages::Message;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;

use subtle_encoding::hex;
use base58::{FromBase58, FromBase58Error, ToBase58};

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct SPHINCSPublicKey {
    #[serde(with = "BigArray")]
    pk: [u8;64]
}

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct SPHINCSSecretKey {
    #[serde(with = "BigArray")]
    sk: [u8;128]
}

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct SPHINCSSignature {
    #[serde(with = "BigArray")]
    signature: [u8;29_792],
}

impl SPHINCSSecretKey {
    pub fn generate() -> (SPHINCSPublicKey,SPHINCSSecretKey) {
        let keypair = keypair();

        let mut pk_array: [u8;64] = [0u8;64];
        let mut sk_array: [u8;128] = [0u8;128];

        pk_array.copy_from_slice(keypair.0.as_bytes());
        sk_array.copy_from_slice(keypair.1.as_bytes());

        return (SPHINCSPublicKey{pk: pk_array},SPHINCSSecretKey{sk: sk_array})
    }
}

impl SPHINCSPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSPublicKey,SlugErrors> {
        let mut pk_array: [u8;64] = [0u8;64];


        if bytes.len() == 64 {
            pk_array.copy_from_slice(bytes);
            return Ok(SPHINCSPublicKey {
                pk: pk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        

    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    pub fn to_usable_type(&self) -> std::result::Result<PublicKeySphincs,SlugErrors> {
        let pk = PublicKeySphincs::from_bytes(self.as_bytes());

        if pk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(pk.unwrap())
        }
    }
    pub fn verify(&self, msg: Message, sig: SPHINCSSignature) -> std::result::Result<bool,VerificationError> {
        let verification = verify_detached_signature(&sig.to_usable_type().unwrap(), msg.as_bytes(), &self.to_usable_type().unwrap())?;

        return Ok(true)

    }
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.pk);
        Ok(String::from_utf8(bytes)?)
    }
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
    pub fn to_base58_string(&self) -> String {
        self.pk.to_base58()
    }
    pub fn from_base58_string<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Vec<u8>, FromBase58Error> {
        let bytes = bs58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
}

impl SPHINCSSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSSecretKey, SlugErrors> {
        let mut sk_array: [u8;128] = [0u8;128];

        if bytes.len() == 128 {
            sk_array.copy_from_slice(bytes);
            
            return Ok(SPHINCSSecretKey {
                sk: sk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    pub fn sign(&self, msg: Message) -> std::result::Result<SPHINCSSignature,SlugErrors> {
        let bytes = detached_sign(msg.as_bytes(), &self.to_usable_type().unwrap());

        let signature = SPHINCSSignature::from_bytes(bytes.as_bytes())?;

        return Ok(signature)
    }
    fn to_usable_type(&self) -> std::result::Result<SecretKeySphincs,SlugErrors> {
        let sk = SecretKeySphincs::from_bytes(self.as_bytes());

        if sk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(sk.unwrap())
        }
    }
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.sk);
        Ok(String::from_utf8(bytes)?)
    }
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
}

impl SPHINCSSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.as_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSSignature,SlugErrors> {
        let mut signature_array: [u8;29_792] = [0u8;29_792];

        if bytes.len() == 29_792 {
            signature_array.copy_from_slice(bytes);

            return Ok(SPHINCSSignature { signature: signature_array })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    fn to_usable_type(&self) -> std::result::Result<DetachedSignatureSphincs,Error> {
        let signature = DetachedSignatureSphincs::from_bytes(&self.to_bytes())?;

        return Ok(signature)
    }
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.signature);
        Ok(String::from_utf8(bytes)?)
    }
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
    pub fn to_base58_string(&self) -> String {
        self.signature.to_base58()
    }
    pub fn from_base58_string<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Vec<u8>, FromBase58Error> {
        let bytes = bs58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
}

#[test]
fn keypair_ls() {
    let keypair = SPHINCSSecretKey::generate();

    let message: Message = Message::new("This is a signed message");

    println!("Public Key Length: {}",keypair.0.as_bytes().len());
    println!("Secret Key Length: {}",keypair.1.as_bytes().len());

    let signature = keypair.1.sign(message).unwrap();

    let length: usize = signature.to_bytes().len();

    println!("SPHINCS+ Signature Length: {}", length);
}