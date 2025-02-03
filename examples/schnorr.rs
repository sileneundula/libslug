use libslug::slugcrypt::internals::signature::schnorr::{SchnorrPublicKey,SchnorrSecretKey,SchnorrSignature};

fn main() {
    let sk = SchnorrSecretKey::generate();
    let signature = sk.sign_with_context("This is a message", "SlugCrypt");
}