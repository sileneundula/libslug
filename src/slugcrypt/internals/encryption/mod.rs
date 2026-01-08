//! # Public Key Encryption (Asymmetric Encryption)
//! 
//! This module contains all components for public key encryption to encrypt/decrypt messages using public keys and their respective private keys (secret keys).
//! 
//! These can be used to encrypt messages across the internet, similar to RSA encryption.
//! 
//! --
//! 
//! This library includes the following:
//! 
//! - [X] ECIES-Curve25519-silene (SHA3) (feature: `ecies-ed25519-sha3`) (Elliptic Curve Public Key Encryption For Messages)
//! - [ ] ECIES-Curve25519-sha2
//! - [X] ML-KEM (Kyber1024) (feature: `kyber1024`)
//! - [ ] ML-KEM (Kyber768)
//! - [ ] RSA

#[cfg(feature = "ecies-ed25519-sha3")]
/// ECIES over Curve25519 using SHA3 (ECIES-ED25519-Silene)
pub mod ecies;

#[cfg(feature = "kyber1024")]
/// Module Lattice Key Encapsulation Encryption using ML_KEM (Kyber)
pub mod ml_kem;