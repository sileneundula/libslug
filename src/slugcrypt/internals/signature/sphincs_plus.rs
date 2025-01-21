use pqcrypto_sphincsplus::sphincsshake256ssimple::*;
use pqcrypto_traits::{Error,Result,sign::{PublicKey,SecretKey,DetachedSignature,SignedMessage}};

pub struct SPHINCSPublicKey {
    pk: [u8;64]
}

pub struct SPHINCSSecretKey {
    sk: [u8;128]
}

pub struct SPHINCSSignature {
    signature: [u8;29_792]
}

impl SPHINCSSecretKey {
    pub fn generate() -> (SPHINCSPublicKey,SPHINCSSecretKey) {
        let keypair = keypair();

        let mut pk_array: [u8;64] = [0u8;64];
        let mut sk_array: [u8;128] = [0u8;128];

        pk_array.copy_from_slice(keypair.0.as_bytes());
        sk_array.copy_from_slice(keypair.1.as_bytes());

        return (SPHINCSPublicKey{pk: pk_array},SPHINCSSecretKey{sk: sk_array})
    }
}