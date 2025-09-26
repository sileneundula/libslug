//use ecdsa::signature::Keypair;
use ecdsa::PrimeCurve;
use ecdsa::signature::Signer;
use ecdsa::signature::RandomizedSigner;
use ecdsa::signature::Keypair;
use k256::ecdsa::{SigningKey, Signature, VerifyingKey};
use k256::Secp256k1;
use rand::rngs::OsRng;

/*
pub struct ECDSAPublicKey([u8;32]);
pub struct ECDSASecretKey([u8;32]);

pub struct ECDSASignature([u8;64]);

impl ECDSASecretKey {
    pub fn generate() -> Self {
        let mut bytes: [u8;32] = [0u8;32];

        let mut os_rng = OsRng;
        let key = k256::ecdsa::SigningKey::random(&mut os_rng);
        let output_bytes = key.to_bytes().as_slice().to_vec();

        bytes.copy_from_slice(&output_bytes);

        ECDSASecretKey(bytes)
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<(ecdsa::Signature<Secp256k1>, ecdsa::RecoveryId), ecdsa::Error> {
        let signature: (ecdsa::Signature<Secp256k1>, ecdsa::RecoveryId) = self.to_usable_type().sign_recoverable(msg.as_ref())?;
        return Ok(signature)
    }
    pub fn to_usable_type(&self) -> Result<SigningKey,ecdsa::Error> {
        let key: ecdsa::SigningKey<Secp256k1> = SigningKey::from_slice(&self.0)?;
        return Ok(key)
    } 
    pub fn to_usable_type_pk(&self) -> VerifyingKey<Secp256k1> {
        self.to_usable_type().verifying_key()?;
    }
    pub fn public_key(&self) -> ECDSAPublicKey {
        let mut output_bytes: [u8;32] = [0u8;32];
        let bytes = self.to_usable_type_pk().to_sec1_bytes();
        let final_bytes = bytes.to_vec();

        if final_bytes.len() == 32 {
            output_bytes.copy_from_slice(final_bytes);
        }
        ECDSAPublicKey(output_bytes)
    }
}

impl ECDSAPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> [u8;32] {
        return self.0
    }
    pub fn to_usable_type(&self) -> Result<VerifyingKey,ecdsa::Error> {
        let key: ecdsa::VerifyingKey<Secp256k1> = VerifyingKey::from_sec1_bytes(&self.0)?;
        return Ok(key)
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: ECDSASignature) {
        
    }
}



#[test]
fn ECDSA() {
    ECDSASecretKey::generate();
}

*/