//! # ShulginSigning
//! 
//! ShulginSigning is a hybrid digital signature scheme using ED25519 and SPHINCS+ (SHAKE256).
//! 
//! It is created by Joseph P. Tortorelli (silene)

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

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSignature {
    pub clsig: ED25519Signature,
    pub pqsig: SPHINCSSignature,
}

impl ShulginKeypair {
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