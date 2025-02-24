use tiny_keccak::Sha3;
use tiny_keccak::Hasher;
use tiny_keccak::Xof;

pub struct Sha3Hasher(usize);

impl Sha3Hasher {
    pub fn new(bits: usize) -> Self {
        match bits {
            224 => Self(224),
            256 => Self(256),
            384 => Self(384),
            512 => Self(512),
            _ => Self(512),
        }
    }
    pub fn hash(&self, data: &[u8]) -> Sha3 {
        match self.0 {
            224 => Sha3::v224(),
            256 => Sha3::v256(),
            384 => Sha3::v384(),
            512 => Sha3::v512(),
            _ => Sha3::v512()
        }
    }
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.hash(data);
        hasher.update(data);
        let mut output = vec![0u8; self.0 / 8];
        hasher.finalize(&mut output);
        output
    }
}