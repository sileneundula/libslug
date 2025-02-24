use serde::{Serialize,Deserialize};
use serde_encrypt::shared_key::SharedKey;

pub struct KeyPairFormat {
    version: u8,
    alg: u16,
    
    is_signer: bool,
    is_encryption: bool,

    public_key: String,
    secret_key: String,
    fingerprint: String, // 8-byte fingerprint
}

impl KeyPairFormat {
    pub fn from_keypair<T: AsRef<str>>(pk: T, sk: T, alg: u16) -> Self {
        Self {
            version: 0u8,
            alg: alg,

            public_key: pk.as_ref().to_string(),
            secret_key: sk.as_ref().to_string(),
            fingerprint: String::from("StaticFingerprint"),
        }
    }
}