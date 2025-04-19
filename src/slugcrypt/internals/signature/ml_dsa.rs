use ml_dsa::{self, KeyGen};
use rand::rngs::OsRng;

pub struct MLDSAPublicKey {
    pub pk: [u8; 1952],
}

pub struct MLDSASecretKey {
    pub sk: [u8; 4032],
}

pub struct MLDSAKeypair {
    pub public_key: MLDSAPublicKey,
    pub secret_key: MLDSASecretKey,
}

pub struct SlugMLDSA;

impl SlugMLDSA {
    pub fn generate() -> MLDSAKeypair {
        let mut rng = OsRng::default();
        let kp = ml_dsa::MlDsa65::key_gen(&mut rng);

        println!("MLDSA Keypair Generated");
        println!("Secret Key: {}", kp.signing_key().encode().len());
        println!("Public Key: {}", kp.verifying_key().encode().len());

        let mut pk_output = [0u8; 1952];
        let mut sk_output = [0u8; 4032];
        pk_output.copy_from_slice(kp.verifying_key().encode().as_ref());
        sk_output.copy_from_slice(kp.signing_key().encode().as_ref());

        let public_key = MLDSAPublicKey { pk: pk_output };
        let secret_key = MLDSASecretKey { sk: sk_output };

        return MLDSAKeypair {
            public_key,
            secret_key,
        }
    }
}

#[test]
fn gen() {
    let keypair = SlugMLDSA::generate();
}