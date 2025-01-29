/// # SlugCSPRNG
/// 
/// Init() initializes the CSPRNG with a password and seed from getrandom(). It uses Argon2id to derive the password. It then uses ChaCha20 to derive the secret.

use securerand_rs::securerand::SecureRandom;
use securerand_rs::rngs::FuschineCSPRNG;

/// # SlugCSPRNG
/// 
/// A CSPRNG using CHACHA20RNG and ARGON2ID
/// 
/// ```rust
/// use libslug::slugcrypt::csprng::SlugCSPRNG;
/// 
/// fn main() {
///     let password: &str = "Thisisapassword";
/// 
///     let csprng = SlugCSPRNG::new(password);
/// }
/// ```
pub struct SlugCSPRNG;

impl SlugCSPRNG {
    /// Initializes the CSPRNG using CHACHA20RNG and Password Derived From Argon2id
    pub fn new(pass: &str) -> [u8;32] {
        SecureRandom::new(pass)
    }
    pub fn os_rand() -> [u8;32] {
        return FuschineCSPRNG::new_32();
    }
}