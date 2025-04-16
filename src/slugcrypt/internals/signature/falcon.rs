use pqcrypto_falcon::falconpadded1024;
use pqcrypto_traits::sign::{PublicKey,SecretKey};

pub struct Falcon1024PublicKey {
    pk: [u8; 1793],
}

pub struct Falcon1024SecretKey {
    sk: [u8; 2305],
}

pub struct SlugFalcon1024;

impl SlugFalcon1024 {
    pub fn generate() -> (Falcon1024PublicKey, Falcon1024SecretKey) {
        let keypair = falconpadded1024::keypair();
        let pk = keypair.0.as_bytes();
        let sk = keypair.1.as_bytes();

        let mut pk_output = [0u8; 1793];
        let mut sk_output = [0u8; 2305];
        pk_output.copy_from_slice(pk);
        sk_output.copy_from_slice(sk);

        let public_key = Falcon1024PublicKey { pk: pk_output };
        let secret_key = Falcon1024SecretKey { sk: sk_output };
        return (public_key, secret_key)
    }
}

#[test]
fn test_falcon_generate() {
    SlugFalcon1024::generate();
}