/// # ECIES over Curve25519 (Encryption)
/// 
/// This module contains the required data to implement ECIES over Curve25519. This is the standard method of encryption.

use ecies_ed25519::PublicKey;
use ecies_ed25519::SecretKey;
use ecies_ed25519::Error;

pub struct ECKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub struct ECPublicKey {
    pub public_key: PublicKey,
}

pub struct ECSecretKey {
    pub secret_key: SecretKey,
}

pub struct CipherText {
    pub cipher_text: Vec<u8>,
}

pub struct Message {
    pub message: Vec<u8>,
}