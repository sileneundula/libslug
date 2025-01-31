use ml_kem::kem::DecapsulationKey;
use ml_kem::EncodedSizeUser;
use ml_kem::MlKem1024;
use ml_kem::KemCore;
use ml_kem::ParameterSet;
use ml_kem::ArraySize;
use ml_kem::array::ArraySize;

use ml_kem::MlKem1024Params;
use rand::rngs::OsRng;

pub struct MLKEMPublicKey {
    pub public_key: [u8;1568],
}

pub struct MLKEMSecretKey {
    pub secret_key: [u8;3168],
}

impl MLKEMSecretKey {
    pub fn generate() -> (MLKEMPublicKey,MLKEMSecretKey) {
        let mut rng = OsRng;

        let mut ek_array: [u8;1568] = [0u8;1568];
        let mut dk_array: [u8;3168] = [0u8;3168];

        let (dk, ek) = MlKem1024::generate(&mut rng);

        if ek.as_bytes().len() == 1_568 && dk.as_bytes().len() == 3_168 {
            ek_array.copy_from_slice(&ek.as_bytes());
            dk_array.copy_from_slice(&dk.as_bytes());

            return (MLKEMPublicKey {
                public_key: ek_array
            },
            MLKEMSecretKey {
                secret_key: dk_array
            })
        }
        else {
            panic!("Did not work right")
        }



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