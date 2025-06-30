use libslug::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature};

#[test]
fn test_ed25519_gen() {
    let _keypair = ED25519SecretKey::generate();
}

#[test]
fn test_ed25519_gen_securerand() {
    let _keypair = ED25519SecretKey::generate_securerand("ed25519_test_keypair");
}

#[test]
fn test_ed25519_to_public() {
    let keypair = ED25519SecretKey::generate();
    let _pk = keypair.public_key().unwrap();
}

#[test]
fn test_ed255199_sign() {
    let keypair = ED25519SecretKey::generate();
    let sig = keypair.sign("This is a test message for ED25519 signing").unwrap();
    let is_valid = keypair.public_key().unwrap().verify(sig, "This is a test message for ED25519 signing").unwrap();

    assert!(is_valid);

}