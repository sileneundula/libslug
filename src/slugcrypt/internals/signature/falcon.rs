//! # FALCON1024
//! 
//! ## Description
//! 
//! FALCON1024 is a post-quantum algorithm for digital signatures.
//! 
//! This implementation includes zeroize, serialization, and more.
//! 
//! ### Key-Size:
//! 
//! **Public-Key Size (in bytes):** 1793
//! **Secret-Key Size (in bytes):** 2305
//! **Signature Size (in bytes):** 1280
//! 
//! ## Features
//! - Generation
//! - Signing
//! - Verification
//! 
//! ## Warning
//! 
//! The Public Key and Secret Key must be kept together. The Public Key *cannot* be derived from the secret key in this implementation.

use pqcrypto_falcon::falconpadded1024;

use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature};

use subtle_encoding::hex::Hex;
use subtle_encoding::Encoding;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

/// # Falcon1024: Public Key
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The public key is 1793-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Verification
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024PublicKey {
    #[serde(with = "BigArray")]
    pk: [u8; 1_793],
}

/// # Falcon1024: Secret Key
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The secret key is 2305-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Signing
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024SecretKey {
    #[serde(with = "BigArray")]
    sk: [u8; 2_305],
}

/// # Falcon1024: Signature
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The signature key is 1280-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Verification
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024Signature {
    #[serde(with = "BigArray")]
    signature: [u8; 1_280],
}

/// # SlugFalcon1024
/// 
/// This is used to generate the keypairs. Both keypairs are required.
pub struct SlugFalcon1024;

impl SlugFalcon1024 {
    /// Generation using OSCSPRNG of Falcon1024 keypairs
    pub fn generate() -> (Falcon1024PublicKey, Falcon1024SecretKey) {
        let keypair = falconpadded1024::keypair();
        let pk = keypair.0.as_bytes();
        let sk = keypair.1.as_bytes();

        let mut pk_output = [0u8; 1793];
        let mut sk_output = [0u8; 2305];
        pk_output.copy_from_slice(pk);
        sk_output.copy_from_slice(sk);

        let public_key = Falcon1024PublicKey { pk: pk_output };
        let secret_key = Falcon1024SecretKey { sk: sk_output };
        return (public_key, secret_key)
    }
}

impl Falcon1024PublicKey {
    /// From Bytes (1793 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pk_array = [0u8; 1793];
        if bytes.len() == 1793 {
            pk_array.copy_from_slice(bytes);
            Ok(Self { pk: pk_array })
        } else {
            Err("Invalid length for Falcon1024 public key".to_string())
        }
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    /// To Hex Upper
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.pk)
    }
    /// To Hex Lower
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.pk)
    }
    /// From Hex Lower
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// To Usable Type
    pub fn to_usable_type(&self) -> falconpadded1024::PublicKey {
        falconpadded1024::PublicKey::from_bytes(&self.pk).unwrap()
    }
    /// # Verify
    /// 
    /// Verifies a message against the Falcon1024 signature.
    /// 
    /// Accepts as input message (as ref \[u8]) and the signature.
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &Falcon1024Signature) -> Result<bool, String> {
        let pkh = self.to_usable_type();
        let sigh = falconpadded1024::DetachedSignature::from_bytes(&signature.as_bytes()).unwrap();
        let result = falconpadded1024::verify_detached_signature(&sigh, message.as_ref(), &pkh);

        return match result {
            Ok(()) => Ok(true),
            Err(e) => Err(format!("Verification failed: {}", e)),
        }
    }
}

impl Falcon1024SecretKey {
    /// From Bytes (2305 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sk_array = [0u8; 2305];
        if bytes.len() == 2305 {
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        } else {
            Err("Invalid length for Falcon1024 secret key".to_string())
        }
    }
    /// As Bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    /// To Usable Type
    pub fn to_usable_type(&self) -> falconpadded1024::SecretKey {
        falconpadded1024::SecretKey::from_bytes(&self.sk).unwrap()
    }
    /// # Falcon1024 Sign
    /// 
    /// Signs a message using Falcon1024 secret key and returns signature. Detatched Signature.
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Falcon1024Signature, String> {
        let skh = self.to_usable_type();
        let signature = falconpadded1024::detached_sign(message.as_ref(), &skh);
        let mut sig_array = [0u8; 1280]; 
        sig_array.copy_from_slice(signature.as_bytes());
        Ok(Falcon1024Signature { signature: sig_array })
    }
    /// To Hex Upper
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.sk)
    }
    /// To Hex Lower
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.sk)
    }
    /// From Hex Lower
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
}

impl Falcon1024Signature {
    /// From Bytes (1280 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sig_array = [0u8; 1280];
        if bytes.len() == 1280 {
            sig_array.copy_from_slice(bytes);
            Ok(Self { signature: sig_array })
        } else {
            Err("Invalid length for Falcon1024 signature".to_string())
        }
    }
    /// as bytes (1280 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
    /// to usable type
    pub fn to_usable_type(&self) -> falconpadded1024::DetachedSignature {
        falconpadded1024::DetachedSignature::from_bytes(&self.signature).unwrap()
    }
    /// To Hex Upper (Constant-Time)
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.signature)
    }
    /// To Hex Lower (Constant-Time)
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.signature)
    }
    /// From Hex Lower (Constant-Time)
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper (Constant Time)
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
}

#[test]
fn test_falcon_generate() {
    let (pk,sk) = SlugFalcon1024::generate();
    let sig = sk.sign(b"Message").unwrap();
    let is_valid = pk.verify(b"Message", &sig).unwrap();
    assert_eq!(is_valid, true);
}