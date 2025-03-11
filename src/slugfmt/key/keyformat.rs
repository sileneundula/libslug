use serde::{Serialize,Deserialize};
use serde_encrypt::shared_key::SharedKey;

pub struct KeyPairFormat {
    version: u8,
    alg: KeypairAlgorithm,
    keytype: KeypairType,

    public_key: String,
    secret_key: String,
    fingerprint: String, // 8-byte fingerprint
}

pub enum KeypairAlgorithm {
    SIG_ED25519,
    SIG_SlugSchnorr,
    SIG_SPHINCS_PLUS,

    ENC_SlugECIES,
    ENC_MLKEM,
}

pub enum KeypairType {
    Signer,
    Encryption,
}

impl KeyPairFormat {
    pub fn from_keypair<T: AsRef<str>>(pk: T, sk: T, alg: KeypairAlgorithm) -> Self {
        Self {
            version: 0u8,
            alg: alg,

            public_key: pk.as_ref().to_string(),
            secret_key: sk.as_ref().to_string(),
            fingerprint: String::from("StaticFingerprint"),
        }
    }
}