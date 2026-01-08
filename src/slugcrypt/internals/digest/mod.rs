//! # Hash Functions (Digests)
//! 
//! This standardized functionality for hash functions is `libslugdigeststandard`
//! 
//! ## Hash Functions
//! 
//! [X] BLAKE2 (BLAKE2s and BLAKE2b)
//! [X] SHA2 (224,256,384*,512)
//! [X] SHA3 (224,256,384,512)
//! [X] BLAKE3
//! 
//! It uses the following terms:
//! 
//! - `update()` | Adds to hash function
//! 
//! ## TODO
//! 
//! - [ ] Add Finalize and Update

#[cfg(feature = "sha3")]
/// SHA3 (224,256,384,512)
pub mod sha3;

#[cfg(feature = "digest")]
/// Digest Functionality
pub mod digest;

#[cfg(feature = "blake2")]
/// BLAKE2 (Blake2s and Blake2b)
pub mod blake2;

#[cfg(feature = "sha2")]
/// SHA2 (224,256,384,512)
pub mod sha2;

#[cfg(feature = "blake3")]
/// BLAKE3 (32-bytes)
pub mod blake3;