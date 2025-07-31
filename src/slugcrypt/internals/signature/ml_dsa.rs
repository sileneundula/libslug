//! # ML-DSA3 (Dilithium65)
//! 
//! ML-DSA Digital Signature Scheme using Level 3 security and the ML-DSA crate. Includes keypair, public key, secret key, signature.
//! 
//! Implements Zeroize and Serialize.
//! 
//! ### Sizes
//! 
//! Public Key Size: 1952
//! Secret Key Size: 4032
//! Signature Size: 3309

use ml_dsa::{self, KeyGen};
use rand::rngs::OsRng;

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
//use subtle_encoding::Hex;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::errors::SlugErrors;

use subtle_encoding::Encoding;
use subtle_encoding::hex;
use subtle_encoding::Error as HexError;

//use hybrid_array::ArrayN;
use hybrid_array_new::ArrayN;

use rand::RngCore;
use rand::CryptoRng;

pub const MLDSA3_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA3_SECRET_KEY_SIZE: usize = 4032;
pub const MLDSA3_SIGNATURE_SIZE: usize = 3309;


/// # MLDSA3: Public Key
/// 
/// The Public Key of MLDSA (Dilithium65)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8; MLDSA3_PUBLIC_KEY_SIZE],
}

/// # MLDSA3: Secret Key
/// 
/// The Secret Key of MLDSA (Dilithium65)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8; MLDSA3_SECRET_KEY_SIZE],
}

/// # MLDSA3: Signature
/// 
/// The Signature of MLDSA (Dilithium65)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3Signature {
    #[serde(with = "BigArray")]
    pub signature: [u8; MLDSA3_SIGNATURE_SIZE],
}

/// # MLDSA3: Keypair (Public Key and Secret Key)
/// 
/// The MLDSA3 Keypair
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3Keypair {
    pub public_key: MLDSA3PublicKey,
    pub secret_key: MLDSA3SecretKey,
}

/// # SlugMLDSA3 (Dilithium65)
/// 
/// Includes Generation
pub struct SlugMLDSA3;

impl SlugMLDSA3 {
    /// Generate Keypair using Operating System Randomness
    pub fn generate() -> MLDSA3Keypair {
        let mut rng: OsRng = OsRng::default();
        let kp: ml_dsa::KeyPair<ml_dsa::MlDsa65> = ml_dsa::MlDsa65::key_gen(&mut rng);

        let mut pk_output: [u8; 1952] = [0u8; 1952];
        let mut sk_output: [u8; 4032] = [0u8; 4032];
        pk_output.copy_from_slice(kp.verifying_key().encode().as_ref());
        sk_output.copy_from_slice(kp.signing_key().encode().as_ref());

        let public_key: MLDSA3PublicKey = MLDSA3PublicKey { pk: pk_output };
        let secret_key: MLDSA3SecretKey = MLDSA3SecretKey { sk: sk_output };

        return MLDSA3Keypair {
            public_key,
            secret_key,
        }
    }
}

impl MLDSA3Keypair {
    /// Retrieve Public Key
    pub fn public_key(&self) -> &MLDSA3PublicKey {
        &self.public_key
    }
    /// Retrieve Secret Key
    pub fn secret_key(&self) -> &MLDSA3SecretKey {
        &self.secret_key
    }
    /// # Sign (with Context) (MLDSA3/Dilithium65)
    /// 
    /// Sign with Context
    pub fn sign<T: AsRef<[u8]>>(&self, message: T, ctx: T) -> Result<MLDSA3Signature, ml_dsa::Error> {
        self.secret_key.sign(message, ctx)
    }
    /// # Verify (MLDSA65)
    /// 
    /// Verify with Context
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, ctx: T, signature: &MLDSA3Signature) -> Result<bool, ml_dsa::Error> {
        self.public_key.verify(message, ctx, signature)
    }
}

impl MLDSA3PublicKey {
    /// From Bytes (1952 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        let mut pk_array: [u8; 1952] = [0u8; 1952];

        if bytes.len() == 1952 {
            pk_array.copy_from_slice(bytes);
            Ok(Self { pk: pk_array })
        } else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// From Hexadecimal (Upper)
    pub fn from_hex<T: AsRef<str>>(s_hex: T) -> Result<Vec<u8>,HexError> {
        let decoded = hex::decode_upper(s_hex.as_ref().as_bytes())?;
        Ok(decoded)
    }
    /// as bytes (1952)
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    /// to byte array (of 1952 bytes)
    pub fn to_bytes(&self) -> [u8;1952] {
        return self.pk
    }
    /// to usable type
    pub fn to_usable_type(&self) -> ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
        let hybrid = hybrid_array_new::ArrayN::<u8, 1952>::from_slice(&self.pk);
        let usable: ml_dsa::VerifyingKey<ml_dsa::MlDsa65> = ml_dsa::VerifyingKey::decode(hybrid);
        return usable;
    }
    /// # Verify (With Context) (MLDSA65)
    /// 
    /// Verifies a given message with certain context given a signature and public key
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, ctx: T, signature: &MLDSA3Signature) -> Result<bool, ml_dsa::Error> {
        let vk = self.to_usable_type();
        let sig = signature.to_usable_type();
        Ok(vk.verify_with_context(message.as_ref(), ctx.as_ref(), &sig))
    }
}

impl MLDSA3SecretKey {
    /// From Bytes (4032 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        let mut sk_array: [u8; 4032] = [0u8; 4032];

        if bytes.len() == 4032 {
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        } else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// From Hexadecimal (Upper)
    pub fn from_hex<T: AsRef<str>>(s_hex: T) -> Result<Vec<u8>,HexError> {
        let decoded = hex::decode_upper(s_hex.as_ref().as_bytes())?;
        Ok(decoded)
    }
    /// as bytes (4032 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    /// to usable type
    pub fn to_usable_type(&self) -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        let hybrid = hybrid_array_new::ArrayN::<u8, 4032>::from_slice(&self.sk);
        let usable: ml_dsa::SigningKey<ml_dsa::MlDsa65> = ml_dsa::SigningKey::decode(hybrid);
        return usable;
    }
    /// # Sign (with context) (MLDSA65)
    /// 
    /// Signs with context
    pub fn sign<T: AsRef<[u8]>>(&self, message: T, ctx: T) -> Result<MLDSA3Signature, ml_dsa::Error> {
        let sk = self.to_usable_type();
        let mut rng = OsRng::default();
        let d = sk.sign_randomized(message.as_ref(), ctx.as_ref(), &mut rng)?;
        
        let sig = MLDSA3Signature::from_bytes(d.encode().as_ref()).unwrap();
        Ok(sig)

    }
}

impl MLDSA3Signature {
    /// From Bytes (3309 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        let mut sig_array: [u8; 3309] = [0u8; 3309];

        if bytes.len() == 3309 {
            sig_array.copy_from_slice(bytes);
            Ok(Self { signature: sig_array })
        } 
        else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// as bytes (3309 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
    /// to usable type
    pub fn to_usable_type(&self) -> ml_dsa::Signature<ml_dsa::MlDsa65> {
        let hybrid = hybrid_array_new::ArrayN::<u8, 3309>::from_slice(&self.signature);
        let usable: ml_dsa::Signature<ml_dsa::MlDsa65> = ml_dsa::Signature::decode(hybrid).unwrap();
        return usable;
    }
}

#[test]
fn gen() {
    let keypair = SlugMLDSA3::generate();
    let signature = keypair.sign("Hello, ML_DSA3!", "Context").unwrap();
    let is_valid = keypair.verify("Hello, ML_DSA3!", "Context", &signature);

    println!("Is_Valid: {}", is_valid.unwrap());


}