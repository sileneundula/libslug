use blake3;

pub struct Blake3Hasher;

impl Blake3Hasher {
    pub fn new() -> Self {
        Self
    }
    pub fn digest<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        let hash = blake3::hash(data.as_ref());
        hash.as_bytes().to_vec()
    }
}