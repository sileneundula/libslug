use ml_kem::MlKem768;
use ml_kem::KemCore;

use rand::rngs::OsRng;

pub struct MLKEMPublicKey {
    public_key: Vec<u8>,
}

pub struct MLKEMSecretKey {
    secret_key: Vec<u8>,
}

impl MLKEMSecretKey {
    pub fn generate() {
        let mut rng = OsRng;

        let (dk, ek) = MlKem768::generate(&mut rng);


    }
}