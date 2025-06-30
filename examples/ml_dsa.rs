use libslug::slugcrypt::internals::signature::ml_dsa::{SlugMLDSA3, MLDSA3Keypair, MLDSA3PublicKey, MLDSA3SecretKey, MLDSA3Signature};

fn main() {
    // Generate MLDSA3 Keypair
    let keypair: MLDSA3Keypair = SlugMLDSA3::generate();

    // Display Public Key
    println!("Public Key: {:?}", keypair.public_key().pk);

    // Display Secret Key
    println!("Secret Key: {:?}", keypair.secret_key().sk);

    // Sign a message
    let message = b"Hello, ML_DSA3!";
    let ctx = b"Context";
    let signature: MLDSA3Signature = keypair.sign(message, ctx).unwrap();

    // Display Signature
    println!("Signature: {:?}", signature.signature);

    // Verify the signature
    let is_valid = keypair.verify(message, ctx, &signature).unwrap();
    println!("Is the signature valid? {}", is_valid);
}