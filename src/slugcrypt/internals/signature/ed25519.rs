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
use crate::slugcrypt::internals::csprng::SlugCSPRNG;
use crate::errors::SlugErrors;



/// ED25519 Public Key (Verifying Key)
/// 
/// 32-byte Key in ED25519
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519PublicKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519SecretKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Debug)]
pub struct ED25519Signature([u8;64]);

impl ED25519SecretKey {
    pub fn generate() -> ED25519SecretKey {
        let csprng = SlugCSPRNG::os_rand();
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes())
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
}


#[test]
fn run() {
    let sk = ED25519SecretKey::generate();
    println!("Secret Key: {:?}", sk);
}