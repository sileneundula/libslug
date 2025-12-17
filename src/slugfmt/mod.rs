//! # SlugFormat
//! 
//! `SlugFormat` is the format used for certificates, secret keys, public keys, encryption keys, among others.
//! 
//! It is broken down into several modules. They are serialized into YAML or TOML.
//! 
//! ## Purpose
//! 
//! Create a format for new keypairs that is easy to use, looks simple, and is interoperable. Use serialization and other parts, as well as traits.
//! 
//! ## Features
//! 
//! - [ ] 
//! 
//! ## Work
//! 
//! - [ ] Extension Names
//!     - [X] .slug
//! - [ ] Serialization
//!     - [ ] Turn bytes into readable text
//!     - [ ] Encrypt Keys
//! 
//! The first module is the standard pass.



pub mod filesystem;

pub mod certificate;
pub mod key;
pub mod encrypt;
pub mod x59cert;