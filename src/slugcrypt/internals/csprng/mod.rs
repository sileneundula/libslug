/// # SlugCSPRNG
/// 
/// Init() initializes the CSPRNG with a password and seed from getrandom(). It uses Argon2id to derive the password. It then uses ChaCha20 to derive the secret.

use securerand_rs::securerand::SecureRandom;

pub struct SlugCSPRNG;

impl SlugCSPRNG {
    /// Initializes the CSPRNG using CHACHA20RNG and Password Derived From Argon2id
    pub fn new(pass: &str) -> [u8;32] {
        SecureRandom::new(pass)
    }
}