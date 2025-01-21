use libslug::slugcrypt::internals::csprng::SlugCSPRNG;


// Uses Argon2id and ChaCha20RNG

fn main() {
    let csprng: [u8; 32] = SlugCSPRNG::new("PasswordToUseToDeriveRandomness");
}