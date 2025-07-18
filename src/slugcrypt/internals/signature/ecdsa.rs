//use ecdsa::signature::Keypair;
use ecdsa::PrimeCurve;
use ecdsa::signature::Signer;
use ecdsa::signature::RandomizedSigner;
use ecdsa::signature::Keypair;
use k256::ecdsa::{SigningKey, Signature};
use rand::rngs::OsRng;

pub struct ECDSAPublicKey([u8;32]);
pub struct ECDSASecretKey([u8;32]);

pub struct ECDSASignature([u8;64]);

impl ECDSASecretKey {
    pub fn generate() -> Self {
        let mut bytes: [u8;32] = [0u8;32];

        let mut os_rng = OsRng;
        let key = k256::ecdsa::SigningKey::random(&mut os_rng);
        let output_bytes = key.to_bytes().as_slice().to_vec();

        bytes.copy_from_slice(&output_bytes);

        ECDSASecretKey(bytes)
    }
}

#[test]
fn ECDSA() {
    ECDSASecretKey::generate();
}
