use pqcrypto_falcon::falconpadded1024;

use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature};

use subtle_encoding::hex::Hex;
use subtle_encoding::Encoding;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

///! Falcon1024 Signature Scheme Implementation
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorith.
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024PublicKey {
    #[serde(with = "BigArray")]
    pk: [u8; 1_793],
}

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024SecretKey {
    #[serde(with = "BigArray")]
    sk: [u8; 2_305],
}

#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct Falcon1024Signature {
    #[serde(with = "BigArray")]
    signature: [u8; 1_280],
}

pub struct SlugFalcon1024;

impl SlugFalcon1024 {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pk_array = [0u8; 1793];
        if bytes.len() == 1793 {
            pk_array.copy_from_slice(bytes);
            Ok(Self { pk: pk_array })
        } else {
            Err("Invalid length for Falcon1024 public key".to_string())
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.pk)
    }
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.pk)
    }
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    pub fn to_usable_type(&self) -> falconpadded1024::PublicKey {
        falconpadded1024::PublicKey::from_bytes(&self.pk).unwrap()
    }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sk_array = [0u8; 2305];
        if bytes.len() == 2305 {
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        } else {
            Err("Invalid length for Falcon1024 secret key".to_string())
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    pub fn to_usable_type(&self) -> falconpadded1024::SecretKey {
        falconpadded1024::SecretKey::from_bytes(&self.sk).unwrap()
    }
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Falcon1024Signature, String> {
        let skh = self.to_usable_type();
        let signature = falconpadded1024::detached_sign(message.as_ref(), &skh);
        println!("Signature Bytes: {}", signature.as_bytes().len());


        let mut sig_array = [0u8; 1280]; 
        sig_array.copy_from_slice(signature.as_bytes());
        Ok(Falcon1024Signature { signature: sig_array })
    }
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.sk)
    }
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.sk)
    }
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
}

impl Falcon1024Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sig_array = [0u8; 1280];
        if bytes.len() == 1280 {
            sig_array.copy_from_slice(bytes);
            Ok(Self { signature: sig_array })
        } else {
            Err("Invalid length for Falcon1024 signature".to_string())
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
    pub fn to_usable_type(&self) -> falconpadded1024::DetachedSignature {
        falconpadded1024::DetachedSignature::from_bytes(&self.signature).unwrap()
    }
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.signature)
    }
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.signature)
    }
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
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