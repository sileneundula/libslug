use ed25519_dalek::{Signer,Verifier};
use ed25519_dalek::ed25519::SignatureEncoding;
use ed25519_dalek::SignatureError;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};
use crate::slugcrypt::internals::csprng::SlugCSPRNG;




#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519PublicKey([u8;32]);

#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519SecretKey([u8;32]);
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Debug)]
pub struct ED25519Signature([u8;64]);

impl ED25519SecretKey {
    pub fn generate() -> ED25519SecretKey {
        let csprng = SlugCSPRNG::os_rand();
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes())
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn to_usable_type(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<ED25519Signature,SignatureError> {
        let signature = self.to_usable_type().try_sign(msg.as_ref())?;


        return Ok(ED25519Signature(signature.to_bytes()))
    }
}


#[test]
fn run() {
    let sk = ED25519SecretKey::generate();
    println!("Secret Key: {:?}", sk)
}