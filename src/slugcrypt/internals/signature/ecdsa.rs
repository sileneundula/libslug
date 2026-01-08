//use ecdsa::signature::Keypair;
use ecdsa::PrimeCurve;
use ecdsa::signature::Signer;
use ecdsa::signature::RandomizedSigner;
use ecdsa::signature::Keypair;
use k256::ecdsa::{SigningKey, Signature, VerifyingKey};
use k256::Secp256k1;
use rand::rngs::OsRng;

use crate::errors::SlugErrors;

pub struct ECDSAPublicKey(pub [u8;32]);
pub struct ECDSASecretKey(pub [u8;32]);

pub struct ECDSASignature(pub [u8;64]);

impl ECDSASignature {
    pub fn from_bytes(bytes: [u8;64]) -> Self {
        return Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut output: [u8;64] = [0u8;64];
        
        if bytes.len() == 64 {
            output.copy_from_slice(bytes);
            Ok(Self(output))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn into_usable_type(&self) -> Result<Signature,SlugErrors> {
        let x = Signature::from_slice(&self.0);

        match x {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
}

impl ECDSASecretKey {
    /// # Generate k256
    /// 
    /// ## Description
    /// 
    /// Generates an ECDSA signing key for secp256k1 with 32 bytes of operating system randomness.
    pub fn generate() -> Self {
        let mut bytes: [u8;32] = [0u8;32];

        let mut os_rng = OsRng;
        let key = k256::ecdsa::SigningKey::random(&mut os_rng);
        let output_bytes = key.to_bytes().as_slice().to_vec();

        bytes.copy_from_slice(&output_bytes);

        ECDSASecretKey(bytes)
    }
    /// # Sign (Recoverable)
    /// 
    /// Sign using ECDSA.
    pub fn sign_recoverable<T: AsRef<[u8]>>(&self, msg: T) -> Result<(ecdsa::Signature<Secp256k1>, ecdsa::RecoveryId), SlugErrors> {
        let signature = self.to_usable_type();
        
        let signingkey = match signature {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure),
        };

        let x: Result<(ecdsa::Signature<Secp256k1>, ecdsa::RecoveryId), ecdsa::Error> = signingkey.sign_recoverable(msg.as_ref());

        let output = match x {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure)
        };

        let output_bytes = output.0.to_bytes();

        return Ok(output)
    }
    /// # To SigningKey
    /// 
    /// Converts To Signing Key
    pub fn to_usable_type(&self) -> Result<SigningKey,ecdsa::Error> {
        let key: ecdsa::SigningKey<Secp256k1> = SigningKey::from_slice(&self.0)?;
        return Ok(key)
    }
    /// # To VerifyingKey
    /// 
    /// Converts To Verifying Key From Secret Key
    pub fn to_usable_type_pk(&self) -> Result<VerifyingKey,ecdsa::Error> {
        let x = self.to_usable_type();

        let key = match x {
            Ok(v) => v,
            Err(_) => return Err(ecdsa::Error::default()),
        };

        return Ok(key.verifying_key().to_owned())
    }
    /// # Public Key
    /// 
    /// Gets Public Key From Secret Key
    pub fn public_key(&self) -> Result<ECDSAPublicKey,ecdsa::Error> {
        let mut output_bytes: [u8;32] = [0u8;32];
        let bytes = self.to_usable_type_pk();

        let pk = match bytes {
            Ok(v) => v,
            Err(_) => return Err(ecdsa::Error::default())
        };
        let bytes = pk.to_sec1_bytes();
        let final_bytes = bytes.to_vec();

        if final_bytes.len() == 32 {
            output_bytes.copy_from_slice(&final_bytes);
        }
        Ok(ECDSAPublicKey(output_bytes))
    }
}

impl ECDSAPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> [u8;32] {
        return self.0
    }
    pub fn from_bytes(bytes: [u8;32]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut output: [u8;32] = [0u8;32];
        
        if bytes.len() == 32 {
            output.copy_from_slice(bytes);
            return Ok(Self(output))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn to_usable_type(&self) -> Result<VerifyingKey,ecdsa::Error> {
        let key: ecdsa::VerifyingKey<Secp256k1> = VerifyingKey::from_sec1_bytes(&self.0)?;
        return Ok(key)
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: ECDSASignature) -> Result<bool,SlugErrors> {
        let x = self.to_usable_type()?;
        let signature = signature.into_usable_type()?;

    }
    pub fn verify_recoverable<T: AsRef<[u8]>>(&self, msg: T, signature: ECDSASignature) {

    }
}



#[test]
fn ECDSA() {
    ECDSASecretKey::generate();
}