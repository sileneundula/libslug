use serde::{Serialize,Deserialize};
use serde_encrypt::shared_key::SharedKey;
use crate::slugcrypt::internals::digest::blake2::SlugBlake2sHasher;
use crate::slugcrypt::internals::digest::digest::SlugDigest;
use serde_encrypt::traits::SerdeEncryptSharedKey;

use crate::slugcrypt::internals::encrypt::chacha20::{EncryptionCipherText,EncryptionKey,EncryptionNonce,SlugEncrypt};

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct KeyPairFormat {
    version: u8,
    platform: String, // SlugCrypt
    alg: KeypairAlgorithm,
    keytype: KeypairType,

    public_key: String, // Hex
    secret_key: String, // Hex (encrypted)
    fingerprint: String, // 8-byte fingerprint
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub enum KeypairAlgorithm {
    SIG_ED25519,
    SIG_SlugSchnorr,
    SIG_SPHINCS_PLUS,

    ENC_SlugECIES,
    ENC_MLKEM,
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub enum KeypairType {
    Signer,
    Encryption,
}

impl KeyPairFormat {
    pub fn from_keypair<T: AsRef<str>>(pk: T, sk: T, alg: KeypairAlgorithm) -> Self {
        let keypairtype = match alg {
            KeypairAlgorithm::SIG_ED25519 => KeypairType::Signer,
            KeypairAlgorithm::SIG_SPHINCS_PLUS => KeypairType::Signer,
            KeypairAlgorithm::SIG_SlugSchnorr => KeypairType::Signer,

            KeypairAlgorithm::ENC_SlugECIES => KeypairType::Encryption,
            KeypairAlgorithm::ENC_MLKEM => KeypairType::Encryption,
        };

        let hasher = SlugBlake2sHasher::new(8).hash(pk.as_ref().to_string());
        let digest = SlugDigest::from_bytes(&hasher).unwrap();
        
        Self {
            version: 0u8,
            platform: "SlugCrypt".to_string(),
            alg: alg,
            keytype: keypairtype,

            public_key: pk.as_ref().to_string(),
            secret_key: sk.as_ref().to_string(),
            fingerprint: digest.to_string().as_str().to_string(),
        }
    }
}

#[test]
fn create() {
    let keypair = KeyPairFormat::from_keypair("SSS", "SSS", KeypairAlgorithm::SIG_ED25519);
}