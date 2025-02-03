use libslug::slugcrypt::internals::signature::schnorr::{SchnorrPublicKey,SchnorrSecretKey,SchnorrSignature};

fn main() {
    let sk = SchnorrSecretKey::generate();
    let pk = sk.public_key().unwrap();
    let signature = sk.sign_with_context("This is a message", "SlugCrypt").unwrap();
    let output = pk.verify_with_context("This is a message", "SlugCrypt", signature);

    if output.is_ok() {
        println!("Valid Signature");
    }
    else {
        println!("Invalid Signature");
    }

}