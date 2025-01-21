use ml_kem::kem::DecapsulationKey;
use ml_kem::EncodedSizeUser;
use ml_kem::MlKem1024;
use ml_kem::KemCore;

use ml_kem::MlKem1024Params;
use rand::rngs::OsRng;

pub struct MLKEMPublicKey {
    pub public_key: [u8;1568],
}

pub struct MLKEMSecretKey {
    pub secret_key: [u8;3168],
}
/*
impl MLKEMSecretKey {
    pub fn generate() -> (MLKEMPublicKey,MLKEMSecretKey) {
        let mut rng = OsRng;

        let (dk, ek) = MlKem1024::generate(&mut rng);

        return (MLKEMPublicKey {
            public_key: ek.as_bytes().to_vec()
        },
        MLKEMSecretKey {
            secret_key: dk.as_bytes().to_vec()
        })

    }
    pub fn to_secret_key(&self) -> DecapsulationKey<MlKem1024Params> {
        DecapsulationKey::from_bytes(&self.secret_key)
    }
}

#[test]
fn main() {
    let (pk,sk) = MLKEMSecretKey::generate();

    println!("Public Key Len: {}",pk.public_key.len());
    println!("Secret Key Len: {}",sk.secret_key.len());
}

*/