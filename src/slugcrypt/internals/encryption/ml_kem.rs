use ml_kem::kem::DecapsulationKey;
use ml_kem::kem::EncapsulationKey;
use ml_kem::EncodedSizeUser;
use ml_kem::MlKem1024;
use ml_kem::KemCore;
use ml_kem::ParameterSet;
use ml_kem::ArraySize;
use ml_kem::kem::{Decapsulate,Encapsulate};
use ml_kem::SharedKey;
use ml_kem::Ciphertext;

use ml_kem::MlKem1024Params;
use rand::rngs::OsRng;
use hybrid_array::Array;
use serde_encrypt::key;

use crate::errors::SlugErrors;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct MLKEMPublicKey {
    #[serde(with = "BigArray")]
    pub public_key: [u8;1568],
}

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct MLKEMSecretKey {
    #[serde(with = "BigArray")]
    pub secret_key: [u8;3168],
}

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize)]
pub struct MLKEMCipherText {
    pub ciphertext: Vec<u8>,
}

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize,PartialEq, Debug)]
pub struct MLKEMSharedSecret {
    pub shared_secret: [u8;32],
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
    pub fn to_usable_type(&self) -> DecapsulationKey<MlKem1024Params> {
        DecapsulationKey::from_bytes(Array::from_slice(&self.secret_key))
    }
    pub fn public_key(&self) -> Result<MLKEMPublicKey,SlugErrors> {
        let bytes = self.to_usable_type().encapsulation_key().as_bytes();
        MLKEMPublicKey::from_bytes(&bytes)
    }
    pub fn decapsulate(&self, ciphertext: MLKEMCipherText) -> MLKEMSharedSecret {
        let key: EncapsulationKey<MlKem1024Params> = EncapsulationKey::from_bytes(Array::from_slice(ciphertext.as_bytes()));

        let shared_secret_output = self.to_usable_type().decapsulate(Array::from_slice(ciphertext.as_bytes())).unwrap();


        
        let mut shared_secret: [u8;32] = [0u8;32];

        let bytes = shared_secret_output.as_slice();

        shared_secret.copy_from_slice(&bytes);

        return MLKEMSharedSecret {
            shared_secret: shared_secret
        }
    }
}

impl MLKEMPublicKey {
    pub fn from_array_bytes(bytes: [u8;1568]) -> Self {
        return Self {
            public_key: bytes 
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut byte_array: [u8;1568] = [0u8;1568];
        
        if bytes.len() == 1568 {
            byte_array.copy_from_slice(&bytes);
            return Ok(Self {public_key: byte_array})
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn to_usable_type(&self) -> EncapsulationKey<MlKem1024Params> {
        EncapsulationKey::from_bytes(Array::from_slice(&self.public_key))
    }
    pub fn encapsulate(&self) -> (MLKEMCipherText,MLKEMSharedSecret) {
        let mut rng = OsRng;
        let (x,sk) = self.to_usable_type().encapsulate(&mut rng).unwrap();
        let ciphertext = MLKEMCipherText {
            ciphertext: x.as_slice().to_vec()
        };

        let mut shared_secret: [u8;32] = [0u8;32];

        let shared = sk.as_slice();

        if shared.len() == 32 {
            shared_secret.copy_from_slice(shared);
        }
        else {
            panic!("Shared Secret Less or More Than 32 bytes")
        }

        return (ciphertext,MLKEMSharedSecret { shared_secret: shared_secret } )
    }
}

impl MLKEMCipherText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn to_usable_type<K: KemCore>(&self) -> Array<u8, <K as KemCore>::CiphertextSize>  {
        let ciphertext: Array<u8, <K as KemCore>::CiphertextSize> = Ciphertext::<K>::try_from(Array::from_slice(&self.ciphertext).to_owned()).unwrap();
        return ciphertext
    }
}

#[test]
fn main() {
    let (pk,sk) = MLKEMSecretKey::generate();

    println!("Public Key Len: {}",pk.public_key.len());
    println!("Secret Key Len: {}",sk.secret_key.len());

}