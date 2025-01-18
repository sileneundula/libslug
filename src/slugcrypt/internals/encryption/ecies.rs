/// # ECIES over Curve25519 (Encryption)
/// 
/// This module contains the required data to implement ECIES over Curve25519. This is the standard method of encryption.

use ecies_ed25519::PublicKey;
use ecies_ed25519::SecretKey;
use ecies_ed25519::Error;

//use rand::RngCore;
use rand::rngs::OsRng;
//use rand::CryptoRng;
pub struct ECIESEncrypt;
pub struct ECIESDecrypt;

pub struct ECKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub struct ECPublicKey {
    pub public_key: PublicKey,
}

pub struct ECSecretKey {
    pub secret_key: SecretKey,
}

pub struct ECCipherText {
    pub ciphertext: Vec<u8>,
}

impl ECIESEncrypt {
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, msg: T) -> Result<Vec<u8>,Error>  {
        let mut csprng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut csprng)?;

        return Ok(ciphertext)
    }
}

impl ECKeyPair {
    pub fn generate() -> ECKeyPair {
        let mut rng = OsRng;

        let (secret_key,public_key) = ecies_ed25519::generate_keypair(&mut rng);
        ECKeyPair {
            public_key,
            secret_key,
        }
    }
    
}

impl ECPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.public_key.to_bytes()
    }
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let public_key = ecies_ed25519::PublicKey::from_bytes(&bytes)?;

        return Ok(Self {
            public_key
        })
    }
}

impl ECSecretKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;

        let secret_key = ecies_ed25519::SecretKey::generate(&mut rng);

        ECSecretKey {
            secret_key
        }
    }
    pub fn to_bytes(&self) -> [u8;32] {
        self.secret_key.to_bytes()
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }
    pub fn from_bytes(bytes: [u8;32]) -> Result<Self,Error> {
        let secret_key = ecies_ed25519::SecretKey::from_bytes(&bytes)?;
        
        return Ok(Self {
            secret_key
        })
    }
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self,Error> {
        let secret_key = ecies_ed25519::SecretKey::from_bytes(bytes)?;

        return Ok(Self {
            secret_key
        })
    }
    /// Converts ECIES-Curve25519 Secret Key To Public Key
    pub fn public_key(&self) -> ECPublicKey {
        let public_key = ecies_ed25519::PublicKey::from_secret(&self.secret_key);

        ECPublicKey {
            public_key
        }
    }
    pub fn encrypt<T: AsRef<[u8]>>(&self, pk: ECPublicKey, msg: T) -> Result<ECCipherText,Error> {
        let mut rng = OsRng;

        let ciphertext = ecies_ed25519::encrypt(&pk.public_key, msg.as_ref(), &mut rng)?;

        return Ok(ECCipherText{
            ciphertext,
        })
    }
}



impl Default for ECKeyPair {
    fn default() -> Self {
        Self::generate()
    }
}