use ml_dsa::{self, KeyGen};
use rand::rngs::OsRng;

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::errors::SlugErrors;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8; 1952],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8; 4032],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MLDSA3Signature {
    #[serde(with = "BigArray")]
    pub signature: [u8; 1952],
}

pub struct MLDSA3Keypair {
    pub public_key: MLDSA3PublicKey,
    pub secret_key: MLDSA3SecretKey,
}

pub struct SlugMLDSA3;

impl SlugMLDSA3 {
    pub fn generate() -> MLDSA3Keypair {
        let mut rng: OsRng = OsRng::default();
        let kp: ml_dsa::KeyPair<ml_dsa::MlDsa65> = ml_dsa::MlDsa65::key_gen(&mut rng);

        println!("MLDSA Keypair Generated");
        println!("Secret Key: {}", kp.signing_key().encode().len());
        println!("Public Key: {}", kp.verifying_key().encode().len());

        let mut pk_output: [u8; 1952] = [0u8; 1952];
        let mut sk_output: [u8; 4032] = [0u8; 4032];
        pk_output.copy_from_slice(kp.verifying_key().encode().as_ref());
        sk_output.copy_from_slice(kp.signing_key().encode().as_ref());

        let public_key: MLDSA3PublicKey = MLDSA3PublicKey { pk: pk_output };
        let secret_key: MLDSA3SecretKey = MLDSA3SecretKey { sk: sk_output };

        return MLDSAKeypair {
            public_key,
            secret_key,
        }
    }
}

impl MLDSA3Keypair {
    pub fn public_key(&self) -> &MLDSA3PublicKey {
        &self.public_key
    }
    pub fn secret_key(&self) -> &MLDSA3SecretKey {
        &self.secret_key
    }
}

impl MLDSA3SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        let mut sk_array: [u8; 4032] = [0u8; 4032];

        if bytes.len() == 4032 {
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        } else {
            Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    pub fn to_usable_type(&self) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, ml_dsa::Error> {
        ml_dsa::SigningKey::decode(&self.sk)
    }
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<ml_dsa::Signature<ml_dsa::MlDsa65>, ml_dsa::Error> {
        let sk = self.to_usable_type()?;
        Ok(sk.sign(message.as_ref()))
    }
}

#[test]
fn gen() {
    let keypair = SlugMLDSA::generate();
}