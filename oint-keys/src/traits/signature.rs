use fixedstr::str256;
use fixedstr::str32;

pub trait OintSignature {
    /// # Encoding
    /// 
    /// Parses the key for encoding
    fn encoding(&self) -> str32;
    /// # Algorithm
    /// 
    /// Tries to get algorithm type
    fn algorithm(&self) -> str256;
}

pub trait OintAddress {
    /// # Derive Address
    /// 
    /// Derives an Address from public key using BLAKE3
    fn derive_address(&self) -> str256;

    fn derive_address_using_hash(&self, hash: str32) -> str256;

    /// # Derive Liberato Address
    /// 
    /// A Liberato Address is a Blake2b with variable digest of the public key. It holds up to 36 namespaces. It goes from 28 bytes - 64 bytes
    /// 
    /// BLAKE2s is used for 28-32 (reserved)
    /// BLAKE2b is used for 32-64
    /// 
    /// So both BLAKE2s and BLAKE2b can be used for 32 variable digest
    fn derive_liberato_address(&self, digest_size: usize) -> str256;

    fn derive_liberato_address_with_nonce(&self, digest_size: usize, nonce: u64) -> str256;

    fn derive_liberato_address_with_config(&self, digest_size: usize, config: Config) -> str256;
}

pub struct Config {
    source: str256,
}