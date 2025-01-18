/// # SlugCSPRNG
/// 
/// Init() initializes the CSPRNG with a password and seed from getrandom(). It uses Argon2id to derive the password. It then uses ChaCha20 to derive the secret.
pub struct SlugCSPRNG;

impl SlugCSPRNG {
    pub fn init(seed: [u8; 32], password: &str) {
        // Initialize the CSPRNG

    }
}