/// # Schnorr Signatures
/// 

use schnorrkel::*;

use zeroize::{Zeroize,ZeroizeOnDrop};
use crate::errors::SlugErrors;
use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;


#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct SchnorrPublicKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct SchnorrSecretKey(#[serde(with = "BigArray")][u8;64]);

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct SchnorrSignature(#[serde(with = "BigArray")][u8;64]);

impl SchnorrSecretKey {
    pub fn generate() -> Self {
        let sk = schnorrkel::SecretKey::generate();
        let sk_bytes = sk.to_bytes();
        return Self(sk_bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> [u8;64] {
        self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut sk_array: [u8;64] = [0u8;64];
        
        if bytes.len() == 64 {
            sk_array.copy_from_slice(bytes);
            return Ok(Self(sk_array))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn to_usable_type(&self) -> Result<schnorrkel::SecretKey,schnorrkel::SignatureError> {
        schnorrkel::SecretKey::from_bytes(&self.0)
    }
    pub fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: T) -> Result<Signature, SignatureError>  {
        let sk = self.to_usable_type()?;
        let pk = self.to_usable_type()?.to_public();
        
        Ok(sk.sign_simple_doublecheck(context.as_ref(), msg.as_ref(), &pk)?)
    }
    pub fn to_public_key_type(&self) -> Result<schnorrkel::PublicKey,schnorrkel::SignatureError> {
        let sk = self.to_usable_type()?;
        Ok(sk.to_public())
    }
}

impl SchnorrPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    pub fn to_usable_type(&self) -> Result<schnorrkel::PublicKey,SignatureError> {
        schnorrkel::PublicKey::from_bytes(&self.0)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut pk_array: [u8;32] = [0u8;32];

        if bytes.len() == 32 {
            pk_array.copy_from_slice(bytes);
            Ok(Self(pk_array))
        }
        else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn verify_with_context<T: AsRef<[u8]>>(&self, msg: T, context: T, signature: SchnorrSignature) -> Result<(), SignatureError> {
        let validation = self.to_usable_type().unwrap().verify_simple(context.as_ref(), msg.as_ref(), &signature.to_usable_type().unwrap());

        if validation.is_err() {
            return Err(validation.unwrap_err())
        }
        else {
            return Ok(validation.unwrap())
        }
    }
}

impl SchnorrSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8;64] {
        self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut sig_array: [u8;64] = [0u8;64];

        if bytes.len() == 64 {
            sig_array.copy_from_slice(bytes);
            Ok(Self(sig_array))
        }
        else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn to_usable_type(&self) -> Result<Signature, SignatureError> {
        schnorrkel::Signature::from_bytes(&self.0)
    }
}

