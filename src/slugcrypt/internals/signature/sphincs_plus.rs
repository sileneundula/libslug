use pqcrypto_sphincsplus::sphincsshake256ssimple::{PublicKey as PublicKeySphincs, SecretKey as SecretKeySphincs};
use pqcrypto_sphincsplus::sphincsshake256ssimple::*;
use pqcrypto_traits::{Error,Result,sign::{PublicKey,SecretKey,DetachedSignature,SignedMessage}};
use crate::errors::SlugErrors;

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

impl SPHINCSPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSPublicKey,SlugErrors> {
        let mut pk_array: [u8;64] = [0u8;64];


        if bytes.len() == 64 {
            pk_array.copy_from_slice(bytes);
            return Ok(SPHINCSPublicKey {
                pk: pk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        

    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    pub fn to_usable_type(&self) -> PublicKeySphincs {
        let pk = PublicKeySphincs::from_bytes(self.as_bytes()).unwrap();
        return pk
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, sig: SPHINCSSignature) {
        verify_detached_signature(sig, msg, pk);
    }
}

impl SPHINCSSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSSecretKey, SlugErrors> {
        let mut sk_array: [u8;128] = [0u8;128];

        if bytes.len() == 128 {
            sk_array.copy_from_slice(bytes);
            
            return Ok(SPHINCSSecretKey {
                sk: sk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
}