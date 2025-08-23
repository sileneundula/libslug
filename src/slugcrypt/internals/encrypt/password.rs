use zeroize::Zeroizing;
use crate::slugcrypt::internals::csprng::SlugCSPRNG;
use super::aes256::{AESCipherText,DecryptAES256,EncryptAES256,EncryptionKey,EncryptionNonce};

pub struct PasswordEncrypt;

impl PasswordEncrypt {
    pub fn generate_key_static(s: &str) -> [u8;32] {
        let rng = SlugCSPRNG::derive_from_password(s);
        return rng
    }
    pub fn generate_key_with_salt(pass: &str, salt: &str) -> [u8;32] {
        let rng = SlugCSPRNG::derive_from_password_with_salt(pass, salt);
        return rng
    }
    pub fn password_encrypt(pass: &str, salt: &str, ephermal_rng: &str) {
        let the_ephermal_rng = EncryptionKey::generate_securerand(ephermal_rng);
        let key = EncryptionKey::generate_deterministic(pass, salt);

        let encrypt_1 = EncryptAES256::encrypt(key,&the_ephermal_rng).unwrap();
    }
}