//! # LibSlug: Digital Signatures
//! 
//! This module contains all the provided digital signature schemes. A digital signature is a cryptographic signature generated using a secret key, producing a signature that can be verified by the public key of the signer's.
//! 
//! The following are provided:
//! 
//! - [X] ED25519
//! 
//! - [X] Schnorr over Ristreto
//! 
//! - [ ] ECDSA
//! 
//! - [ ] ED448
//! 
//! - [X] FALCON1024
//! 
//! - [X] ML-DSA (Dilithium65)
//! 
//! - [X] SPHINCS+ (SHAKE256) (Level 5)
//! 
//! - [ ] Lamport Signatures
//! 
//! - [ ] Winternitz One-Time Signatures (WOTS)

/// SPHINCS+ (SHAKE256) (255bit security) (smaller signature version)
pub mod sphincs_plus;

/// ED25519 Signature
pub mod ed25519;


/// Schnorr Digital Signature
pub mod schnorr;

/// ECDSA
pub mod ecdsa;

/// FALCON1024
pub mod falcon;

/// MLDSA65
pub mod ml_dsa;

/// ED448
pub mod ed448;


/// One-Time Signatures (Lamport Signatures, Winternitz-OTS)
//#[cfg(feature = "OTS")]
pub mod onetimesigs;