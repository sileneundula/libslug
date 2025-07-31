//! \[Audited] AES256-GCM
//! 
//! AES256-GCM is a symmetric encryption algorithm that uses block ciphers and is used by multiple organizations, entities, and even the military.
//! 
//! It is secure at Level 5, boasting a large amount of security for symmetric encryption.
//! 
//! ## Contents
//! 
//! 1. The `EncryptionKey` is 32-bytes in size, implements zeroize, and can be generated a variety of ways
//! 2. The `EncryptionNonce` is 12-bytes in size, implements zeroize, and is generated using operating system randomness on encryption call.
//! 3. The `AESCipherText` is a vector of bytes that contains the data that needs to be decrypted using the `EncryptionKey` and `EncryptionNonce`
//! 
//! It uses the interface:
//! 
//! - AESEncrypt
//! - AESDecrypt
//! 
//! ## Encryption Process
//! 
//! The encryption process is the following:
//! 
//! 1. Generate an `EncryptionKey` (using the various methods of generation available)
//! 2. Encrypt the data with the `EncryptionKey`, generating an `EncryptionNonce` and `AESCipherText`
//! 
//! ## Decryption Process
//! 
//! The decryption process is the following:
//! 
//! 1. Use the `EncryptionKey`, `EncryptionNonce`, and `AESCipherText` to decrypt the data and retrieve an output
//! 2. Use the ouputted data for intended purposes.
//! 
//! ## Security
//! 
//! This AES256-GCM crate has been audited already and takes measures to ensure safety/security.
//! 
//! If any vulnerabilties are found, please report them.

/// # AES256 Encryption Key
/// 
/// **AES-KEY:** 32 bytes in size
/// 
/// Implements Zeroize
/// 
/// ## Features
/// 
/// ### Generation
/// - Generation from Operating System
/// - Generation From SecureRand (Using Argon2id and Ephermal Password)
/// - Generation From Deterministic Password + Salt Using CHACHA20RNG
/// 
/// ### Conversion
/// - Conversion To Hexadecimal
/// - Conversion To Bytes
#[derive(Clone,Debug,Zeroize,ZeroizeOnDrop)]
pub struct EncryptionKey([u8;32]);

/// # AES256 Encryption Nonce
/// 
/// 12 bytes in size
/// 
/// ## Features
/// 
/// - Conversion To Bytes
/// - Conversion To Hexadecimal
#[derive(Clone,Debug,Zeroize,ZeroizeOnDrop)]
pub struct EncryptionNonce([u8;12]);

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};


use hybrid_array::Array;
use subtle_encoding::hex;
use base58::{FromBase58,ToBase58,FromBase58Error};
use zeroize::{Zeroize,ZeroizeOnDrop};
use crate::slugfmt::key::encryptkey::SlugCipherText;

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// # \[Constant-Time] To Hexadecimal
    /// 
    /// Converts the Encryption Key to Hexadecimal
    pub fn to_hex(&self) -> Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode(self.as_bytes());
        String::from_utf8(bytes)
    }
    /// # \[Constant-Time] From Hexadecimal
    /// 
    /// Converts the Hexadecimal Encryption Key Back To Key (Self)
    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Self(key)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Self(key)
    }
    /// # SecureRand Generate
    /// 
    /// Generate a Secure Key Using SecureRand (ChaCha20RNG + Argon2id + Ephermal Password)
    pub fn generate_securerand(pass: &str) -> [u8;32] {
        let rng = securerand_rs::securerand::SecureRandom::new(pass);
        return rng
    }
    /// # Generate From Operating System
    /// 
    /// Generates a Secure Key From The Operating System Entropy
    pub fn generate() -> Self {
        let key: [u8;32] = crate::slugcrypt::internals::csprng::SlugCSPRNG::os_rand();
        return Self(key)
    }
    /// # Generates Determinstically From Password and Salt (Salt must be saved to be deterministic)
    pub fn generate_deterministic(pass: &str, salt: &str) -> Self {
        let key = crate::slugcrypt::internals::csprng::SlugCSPRNG::derive_from_password_with_salt(pass, salt);
        return Self(key)
    }
}

impl EncryptionNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Constant-Time conversion to hexadecimal
    pub fn to_hex(&self) -> Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode(self.as_bytes());
        String::from_utf8(bytes)
    }
    /// Constant-Time conversion from hexadecimal
    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes);
        Self(nonce)
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(bytes);
        Self(nonce)
    }
}

/// # EncryptAES256
/// 
/// Encrypts Using AES256-GCM
pub struct EncryptAES256;

/// # DecryptAES256
/// 
/// Decrypts Using AES256-GCM
pub struct DecryptAES256;

/// # AES256 CIPHERTEXT
/// 
/// - Implements Zeroize
/// 
/// - CipherText (Nonce needed)
/// 
/// ## Features
/// - To and From Bytes
/// - To and From Base58
/// - To and From Hexadecimal (Constant-Time)
/// - \[silene/libslug/Cert] To SlugCipherText
/// 
#[derive(Clone,Debug,Zeroize,ZeroizeOnDrop)]
pub struct AESCipherText {
    pub ciphertext: Vec<u8>,
}

impl AESCipherText {
    pub fn as_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
    /// # AES256 CipherText (To Base58)
    /// 
    /// To Base58 (Not Constant-Time)
    pub fn bs58(&self) -> String {
        self.ciphertext.to_base58()
    }
    /// # AES256 CipherText (To Hexadecimal)
    /// 
    /// To Hexadecimal (Constant-Time)
    pub fn to_hex(&self) -> Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode(self.as_bytes());
        String::from_utf8(bytes)
    }
    /// # AES256 CipherText (From Hexadecimal)
    /// 
    /// From Hexadecimal (Constant-Time)
    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        Self {
            ciphertext: bytes,
        }
    }
    /// # AES256 CipherText (From Base58)
    /// 
    /// From Base58 (Not Constant-Time)
    pub fn from_bs58(s: &str) -> Result<Self,FromBase58Error> {
        let bs58 = s.from_base58()?;

        return Ok(Self {
            ciphertext: bs58
        })
    }
    /// For Formatting (silene/libslug/cert)
    pub fn to_slugciphertext(self, name: String) -> SlugCipherText {
        SlugCipherText::aes256(name, self)
    }
    /// For Formatting (silene/libslug/cert)
    pub fn from_slugciphertext(s: SlugCipherText) -> Self {
        Self {
            ciphertext: s.ciphertext.from_base58().unwrap()
        }
    }
}

impl EncryptAES256 {
    /// # AES256-GCM Encryption
    /// 
    /// **Note:** Make sure you do not lose the `nonce`
    /// 
    /// This function encrypts data (as a reference to bytes), using an EncryptionKey of 32-bytes which can be pre-generated but must be kept secret.
    /// 
    /// A 12-byte `Nonce` is generated from operating system randomness and returned, as well as the CipherText.
    /// 
    /// **Returns:** (CipherText, Nonce)
    /// **Required For Decryption:** (CipherText, Nonce, EncryptionKey)
    /// **Nonce:** 12-byte generated by Operating System on Function Call and Returned With CipherText.
    /// 
    /// ## Example Code
    /// 
    /// This code example shows encrypting/decrypting using AES256-GCM.
    /// 
    /// ```rust
    /// use libslug::slugcrypt::internals::encrypt::aes256::*;
    /// 
    /// fn main() {
    ///     // Key Generation
    ///     let key = EncryptionKey::generate();
    ///     // Data to be encrypted
    ///     let data = b"Hello, world! This is libslug and this data is being encrypted by AES256-GCM (Audited)";
    ///     // Encryption + Decryption Proccess
    ///     let encrypted = EncryptAES256::encrypt(key.clone(), data).unwrap();
    ///     let decrypted = DecryptAES256::decrypt(key.clone(), encrypted.1, encrypted.0).unwrap();
    ///     
    ///     // Assert The Data Is The Same
    ///     assert_eq!(data.to_vec(), decrypted);
    /// }
    /// ```
    pub fn encrypt<T: AsRef<[u8]>>(key_s: EncryptionKey, data: T) -> Result<(AESCipherText,EncryptionNonce), aes_gcm::Error> {
        // Key Array
        let key_array: [u8; 32] = key_s.as_bytes().try_into().unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data.as_ref())?;
        
        Ok(
            (
                AESCipherText {ciphertext} , EncryptionNonce::from_bytes(nonce.as_slice())
            )
        )
    }
}

impl DecryptAES256 {
    /// # AES256-GCM Decryption
    /// 
    /// ## Description
    /// 
    /// This is the decryption function for AES256GCM. It requires:
    /// 
    /// 1. **EncryptionKey:** 32-byte encryption key used to encrypt the data
    /// 2. **EncryptionNonce:** 12-byte nonce generated from operating system during encryption
    /// 3. **CipherText:** A vector of bytes that are decoded to reveal the data.
    /// 
    /// ## Security
    /// 
    /// By default, all types implement zeroize.
    /// 
    /// Lookout for nonce reuse attacks.
    /// 
    /// ## Example Code
    /// 
    /// This code example shows the encryption/decryption process using AES256-GCM (Audited).
    /// 
    /// ```rust
    /// use libslug::slugcrypt::internals::encrypt::aes256::*;
    /// 
    /// fn main() {
    ///     // Key Generation (there are multiple methods to generate the key based on different security threats)
    ///     let key = EncryptionKey::generate();
    ///     // Data to be encrypted
    ///     let data = b"Hello, world! This is libslug and this data is being encrypted by AES256-GCM (Audited)";
    ///     // Encryption + Decryption Proccess
    ///     let encrypted = EncryptAES256::encrypt(key.clone(), data).unwrap();
    ///     let decrypted = DecryptAES256::decrypt(key.clone(), encrypted.1, encrypted.0).unwrap();
    ///     
    ///     // Assert The Data Is The Same
    ///     assert_eq!(data.to_vec(), decrypted);
    /// }
    /// ```
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, data: AESCipherText) -> Result<Vec<u8>, aes_gcm::Error> {
        // Key Array
        let key_array: [u8; 32] = key.as_bytes().try_into().unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce.as_bytes());
        let plaintext = cipher.decrypt(nonce, data.as_bytes())?;
        
        Ok(plaintext)
    }
}