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
//! - ECIES-Curve25519-silene (Elliptic Curve Public Key Encryption For Messages)
//! - ML-KEM (Kyber1024) (will add Kyber768)
//! 
//! In the future, I plan to add:
//! - RSA

/// ECIES over Curve25519
pub mod ecies;

/// Module Lattice Key Encapsulation Encryption using ML_KEM (Kyber)
pub mod ml_kem;