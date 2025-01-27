use libslug::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSecretKey,SPHINCSSignature};
use libslug::slugcrypt::internals::messages::Message;

#[test]
fn sphincs_sign() {
    // Message
    let message = Message::new("This is a message struct that uses UTF-8 to be signed by SPHINCS+");
    
    // Keypair
    let keypair: (SPHINCSPublicKey, SPHINCSSecretKey) = SPHINCSSecretKey::generate();


    // Signing Message
    let signature = keypair.1.sign(message.clone()).unwrap();

    // Boolean
    let is_valid_signature = keypair.0.verify(message.clone(), signature).unwrap();

    // Asserts Valid Signature
    assert!(is_valid_signature);
}