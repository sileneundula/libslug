use libslug::slugcrypt::internals::encryption::ecies::*;

/// # Process
/// 
/// This process is the encryption process from Alice to Bob using Keypairs, PublicKeys, and SecretKeys.


fn main() {
    // Generate Keypair For Alice (ECIES-CURVE25519) from OSCSPRNG to demonstrate generation (not required for encryption)
    let sk_alice: ECSecretKey = ECSecretKey::generate();
    
    // The Message As A UTF-8 str.
    let msg_alice: &str = "Hello, this is a UTF-8 String to be encrypted to ciphertext using AES-GCM, SHA2, and HKDF.";
    
    // Generate Secret Key For Bob (ECIES-CURVE25519) from OSCSPRNG
    let sk_bob: ECSecretKey = ECSecretKey::generate();
    // Retrieve Public Key From Bob's Secret Key For Encryption
    let pk_bob: ECPublicKey = sk_bob.public_key();

    

    // Ciphertext For Bob to Decrypt (does not use secret key)
    let ciphertext = ECIESEncrypt::encrypt(pk_bob, msg_alice);

    // Decode Using Bob's Secret Key
    let decoded_message = ECIESDecrypt::decrypt(sk_bob, ciphertext.unwrap());

    // Message (as UTF-8 str)
    let message_as_utf8 = decoded_message.unwrap().message().unwrap().to_string();

    // Print Message
    println!("Message: {}",message_as_utf8);

}