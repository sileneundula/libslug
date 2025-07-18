use leslie_lamport::Algorithms;
use leslie_lamport::LamportKeyPair;
use leslie_lamport::LamportSignature;

pub struct PublicKey(Vec<u8>);
pub struct SecretKey(Vec<u8>);
pub struct Signature(Vec<u8>);

pub struct LamportConfig {
    hash: Algorithms, // Algorithm
    n: usize, // number of keypairs generated to sign with
    d: usize, // size of secret key + signature
}

impl LamportConfig {
    pub fn new(hash: Algorithms, n: usize, d: usize) -> Self {
        Self {
            hash: hash,
            n: n,
            d: d,
        }
    }
    pub fn default() -> Self {
        Self {
            hash: Algorithms::BLAKE2B,
            n: 64, // 1024 keypairs 1024*32=32_768 bytes
            d: 32, // Secret Size
        }
    }
}




fn run() {
    //LamportKeyPair::generate_advanced(hash, n, d)
}