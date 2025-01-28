use libslug::slugcrypt::internals::{messages::Message, signature::sphincs_plus::{SPHINCSPublicKey, SPHINCSSecretKey, SPHINCSSignature}};


// SPHINCS+ Signature

fn main() {
    let (pk,sk) = SPHINCSSecretKey::generate();
    let message = Message::new("SPHINCS+ Signature");
    let signature = sk.sign(message.clone()).unwrap();

    let is_valid: bool = pk.verify(message.clone(),signature).unwrap();
    assert!(is_valid);
}