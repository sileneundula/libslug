/// SPHINCS+ (SHAKE256) (255bit security) (smaller signature version)
pub mod sphincs_plus;

/// ED25519 Signature
pub mod ed25519;


/// Schnorr Digital Signature
pub mod schnorr;

pub mod ecdsa;

pub mod falcon;

pub mod ml_dsa;

pub mod ed448;


/// One-Time Signatures (Lamport Signatures, Winternitz-OTS)
//#[cfg(feature = "OTS")]
pub mod onetimesigs;