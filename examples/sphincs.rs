use libslug::slugcrypt::internals::{messages::Message, signature::sphincs_plus::{SPHINCSPublicKey, SPHINCSSecretKey, SPHINCSSignature}};


// SPHINCS+ Signature

fn main() {
    let (pk,sk) = SPHINCSSecretKey::generate();
    let message = "SPHINCS+ Signature";
    let signature = sk.sign(message).unwrap();

    let is_valid: bool = pk.verify(message,signature).unwrap();
    assert!(is_valid);
}