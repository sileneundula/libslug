use super::basics::SigningAlgorithms;
use crate::slugcrypt::internals::digest::blake2::SlugBlake2sHasher;
use crate::slugcrypt::internals::digest::digest::SlugDigest;
use serde::{Serialize, Deserialize};
use subtle_encoding::hex;


/// # Signing Section
/// 
/// Algorithm is chosen using an enum.
/// 
/// Public Key is UPPER-HEX ENCODED.
/// 
/// Fingerprint is 6-bytes.


pub struct Signing {
    alg: SigningAlgorithms,
    
    pk: String,
    fingerprint: String, // Fingerprint (0xFFFFFFFFFFFF)
    signature: String,
}

impl Signing {
    pub fn new(alg: SigningAlgorithms, pk: String, signature: String) -> Self {
        let pk_bytes = hex::decode_upper(&pk).unwrap();
        // Create a fingerprint using the first 6 bytes of the public key
        // (which is assumed to be a hex string)
        let hasher = SlugBlake2sHasher::new(8).hash(&pk_bytes);
        let fingerprint = SlugDigest::from_bytes(&hasher).unwrap();
        
        Self {
            alg,
            pk,
            fingerprint: fingerprint.to_string().as_str().to_string(),
            signature,
        }
    }
}