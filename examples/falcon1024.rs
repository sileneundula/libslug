use libslug::slugcrypt::internals::signature::falcon::{Falcon1024PublicKey, Falcon1024SecretKey, Falcon1024Signature, SlugFalcon1024};

fn main() {
    // Generate Falcon1024 Keypair
    let (public_key, secret_key) = SlugFalcon1024::generate();

    // Display Public Key
    println!("Public Key: {:?}", public_key.as_bytes());

    // Display Secret Key
    println!("Secret Key: {:?}", secret_key.as_bytes());

    // Sign a message
    let message = b"Hello, Falcon1024!";
    let signature = secret_key.sign(message).unwrap();
    
    // Display Signature
    println!("Signature: {:?}", signature.as_bytes());

    // Verify the signature
    let is_valid = public_key.verify(message, &signature).unwrap();
    println!("Is the signature valid? {}", is_valid);
}