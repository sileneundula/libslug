//use ecdsa::signature::Keypair;
use ecdsa::PrimeCurve;
use ecdsa::signature::Signer;
use ecdsa::signature::RandomizedSigner;
use ecdsa::signature::Keypair;
use k256::ecdsa::{SigningKey, Signature, VerifyingKey};
use k256::Secp256k1;
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
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> {

    }
    pub fn to_usable_type(&self) -> SigningKey<Secp256k1> {
        SigningKey::from_bytes(&self.0)
    }
    pub fn to_usable_type_pk(&self) -> VerifyingKey<Secp256k1> {
        self.to_usable_type().verifying_key()
    }
    pub fn public_key(&self) -> ECDSAPublicKey {
        let bytes = self.to_usable_type_pk().to_sec1_bytes();
        ECDSAPublicKey(bytes)
    }
}

#[test]
fn ECDSA() {
    ECDSASecretKey::generate();
}
