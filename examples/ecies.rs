use libslug::slugcrypt::internals::encryption::ecies::*;

/// # Process
/// 
/// This process is the encryption process from Alice to Bob using Keypairs, PublicKeys, and SecretKeys.


fn main() {
    // Generate Keypair For Alice (ECIES-CURVE25519) from OSCSPRNG to demonstrate generation (not required for encryption)
    let sk_alice: ECKeyPair = ECSecretKey::generate();
    
    // Generate Secret Key For Bob (ECIES-CURVE25519) from OSCSPRNG
    let sk_bob: ECSecretKey = ECSecretKey::generate();
    // Retrieve Public Key From Bob's Secret Key For Encryption
    let pk_bob: ECPublicKey = sk.public_key();

    // The Message As A UTF-8 str.
    let msg_alice: &str = "Hello, this is a UTF-8 String to be encrypted to ciphertext using AES-GCM, SHA2, and HKDF.";

    let ciphertext = ECIESEncrypt::encrypt(pk_bob, msg_alice);
}