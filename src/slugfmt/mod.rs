//! # SlugFormat
//! 
//! SlugFormat is the format used for certificates, secret keys, public keys, encryption keys, among others.
//! 
//! It is broken down into several modules. They are serialized into YAML or TOML.
//! 
//! The first module is the standard pass.



pub mod filesystem;

pub mod certificate;
pub mod key;
pub mod encrypt;