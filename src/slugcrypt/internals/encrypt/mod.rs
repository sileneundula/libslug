//! # Symmetric Encryption
//! 
//! This module contains symmetric encryption algorithms. These algorithms can be used to encrypt and decrypt data using an encryption key. A nonce is automatically generated during encryption and is required for decryption.
//! 
//! ## Algorithms Implemented
//! 
//! [X] AES256-GCM (Block Cipher)
//! [X] XCHACHA20-POLY1305 (Stream Cipher) (Extended Nonce)
//! [ ] MORUS

/// XCHACHA20-POLY1305 Encryption/Decryption With Extended Nonce
pub mod chacha20;

/// AES256-GCM
pub mod aes256;

/// Morus AEAD
pub mod morus;