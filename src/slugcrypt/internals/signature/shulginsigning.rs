//! # ShulginSigning
//! 
//! ShulginSigning is a hybrid digital signature scheme using ED25519 and SPHINCS+ (SHAKE256).
//! 
//! ## Encoding
//! 
//! ### Public Key
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ PK (Upper-Hex)
//! 
//! ### Signature
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ Signature (Base58)
//! 
//! It is created by Joseph P. Tortorelli (silene)

use std::f32::consts::E;
use std::string::FromUtf8Error;

use crate::slugcrypt::internals::messages::Message;
use crate::slugcrypt::internals::signature::ed25519::{ED25519SecretKey,ED25519PublicKey,ED25519Signature};
use crate::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSecretKey,SPHINCSSignature};
use crate::errors::SlugErrors;
use crate::errors::SlugErrorAlgorithms;

use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginKeypair {
    pub clpk: ED25519PublicKey,
    pub pqpk: SPHINCSPublicKey,
    
    pub clsk: Option<ED25519SecretKey>,
    pub pqsk: Option<SPHINCSSecretKey>,
}

pub struct ShulginKeypairCompact {
    pub public_key: String,
    pub secret_key: Option<String>,
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSignature {
    pub clsig: ED25519Signature,
    pub pqsig: SPHINCSSignature,
}

pub struct ShulginSignatureCompact {
    pub signature: String,
}

impl ShulginSignatureCompact {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = ed25519.to_hex_string();
        let sphincs_sig_bs58 = sphincs.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return Self {
            signature: output
        }
    }
    pub fn as_string(&self) -> &str {
        &self.signature
    }
    pub fn to_string(&self) -> String {
        self.signature.clone()
    }
    pub fn from_str<T: AsRef<str>>(compact: T) -> Self {
        return Self {
            signature: compact.as_ref().to_string()
        }
    }
    pub fn into_shulginsignature(&self) -> Result<ShulginSignature, SlugErrors> {
        let manipulated_string = self.to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(ShulginSignature {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }

    }
}

impl ShulginKeypair {
    pub fn from_public_key(ed25519pk: ED25519PublicKey, sphincspk: SPHINCSPublicKey) -> Self {
        return Self {
            clpk: ed25519pk,
            pqpk: sphincspk,

            clsk: None,
            pqsk: None,
        }
    }
    pub fn generate() -> Self {
        let cl = ED25519SecretKey::generate();
        let clpk = cl.public_key().unwrap();
        let (pq_pk,pq_sk) = SPHINCSSecretKey::generate();

        return Self {
            clpk: clpk,
            pqpk: pq_pk,

            clsk: Some(cl),
            pqsk: Some(pq_sk)
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Result<ShulginSignature,SlugErrors> {
        if self.pqsk.is_some() && self.pqsk.is_some() {
            let cl_sig = self.clsk.clone().unwrap().sign(data.as_ref());
            let pq_sig = self.pqsk.clone().unwrap().sign(data.as_ref());

            if cl_sig.is_err() || pq_sig.is_err() {
                return Err(SlugErrors::SigningFailure)
            }
            else {
                Ok(
                    ShulginSignature {
                    clsig: cl_sig.unwrap(),
                    pqsig: pq_sig.unwrap(),
                    }
                )
            }



        }
        else {
            return Err(SlugErrors::SigningFailure)
        }
    }
    pub fn verify<T: AsRef<[u8]>>(&self, data: T, signature: ShulginSignature) -> Result<bool,SlugErrors> {
        let cl_is_valid = self.clpk.verify(signature.clsig.clone(),data.as_ref());
        let pq_is_valid = self.pqpk.verify(data.as_ref(), signature.pqsig.clone());

        if cl_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ED25519))
        }
        else if pq_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            if cl_is_valid.unwrap() == true && pq_is_valid.unwrap() == true {
                return Ok(true)
            }
            else {
                return Ok(false)
            }
        }
    }
}

impl ShulginSignature {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        return Self {
            clsig: ed25519,
            pqsig: sphincs,
        }
    }
    pub fn import(signature_compact: ShulginSignatureCompact) {
        return 
    }
    pub fn into_ss_format(&self) -> String {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = self.clsig.to_hex_string();
        let sphincs_sig_bs58 = self.pqsig.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return output
    }
    pub fn from_ss_format<T: AsRef<str>>(ss_format: T) -> Result<Self,SlugErrors> {
        let manipulated_string = ss_format.as_ref().to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(Self {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }




    }
}

/// Naive Version Of ShulginSigning Compact Signature Verification
fn verify_signature_compact<T: AsRef<str>>(s: T) -> Result<bool,SlugErrors> {
    let manipulated_string = s.as_ref().to_string();

    let colon_count = manipulated_string.chars().filter(|c| *c == ':').count();

    if manipulated_string.contains(":") == true && colon_count == 1 {
        {
            let x: Vec<&str> = manipulated_string.split(":").collect();
            if x[0].len() != 128 {
                return Err(SlugErrors::Other(String::from("ED25519 Hexadecimal not equal to 128 chars.")))
            }
            else {
                return Ok(true)
            }
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Does Not Contain Colon Or Contains Too Many Colons")))
    }
}

fn key_to_compact(keypair: &ShulginKeypair) -> Result<String, FromUtf8Error> {
    let mut output: String = String::new();
    
    let delimiter = ":";
    
    let ed25519_pk = &keypair.clpk;
    let sphincs_pk = &keypair.pqpk;

    output.push_str(&ed25519_pk.to_hex_string());
    output.push_str(delimiter);
    output.push_str(&sphincs_pk.to_hex_string()?);

    return Ok(output)
}

fn from_public_key_compact<T: AsRef<str>>(ss_pk: T) -> Result<ShulginKeypair,SlugErrors> {
    let x = ss_pk.as_ref().to_string();

    let keys: Vec<&str> = x.split(":").collect();

    let hex_str = ED25519PublicKey::from_hex_string(keys[0]).unwrap();

    let mut byte_array: [u8;32] = [0u8;32];

    if hex_str.len() == 32 {
        byte_array.copy_from_slice(&hex_str)
    }

    if keys.len() == 2 {
        if keys[0].len() == 64 && keys[1].len() == 128 {
            return Ok(ShulginKeypair {
                clpk: ED25519PublicKey::from_bytes(byte_array),
                pqpk: SPHINCSPublicKey::from_hex_string_final(keys[1])?,

                clsk: None,
                pqsk: None,
            })
        }
        else {
            return Err(SlugErrors::Other(String::from("Error when compacting key for shulgin signing.")))
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Key Length Too High")))
    }

}