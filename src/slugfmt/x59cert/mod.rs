//! # X59 Certificate
//! 
//! ## Outline
//! 
//! - [X] Basic Essentials
//!     - [X] Encryption
//!     - [X] Public Key, Private Key Pair
//!     - [X] Serialization to easy to read format (Base58 for public keys)
//! 
//! 
//! - [ ] Signatures
//!     - [ ] Signing the Public Key
//!     - [X] Signing the digest of the public key
//!     - [ ] Signing a request from a server or peer to peer application

use crate::slugcrypt::traits::X59Certificate;
use crate::slugcrypt::api::SlugDigest;

pub mod storage;



/// # [silene/slugfmt/x59cert] X59Cert
/// 
/// Contains the Public Key as a generic.
pub struct X59Cert<T: X59Certificate + Clone> {
    pub pkh: T,
}

// TODO: Add implementation

impl X59Certificate for X59Cert {
    fn into_certificate<T: X59Certificate>(&self) -> X59Cert<T> {
        
    }
}

pub struct X59CertLocalMetadata {
    pub local_id: String, // 6-bytes
    pub local_keypair_identity: String, // 8-bytes
    pub local_unique_name: String,
}

impl X59CertLocalMetadata {
    /*
    pub fn new<H: AsRef<str>, T: X59Certificate>(cert: X59Cert<T>, name: H) {
        cert.pkh
    }
    
    fn digest_of_public_key<T: X59Certificate>(cert: X59Cert<T>) {

        SlugDigest::blake2s(6, data)
    }
    */
}