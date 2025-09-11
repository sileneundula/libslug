use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
use rand::rngs::OsRng;

pub struct ED448PublicKey(pub [u8;57]);

pub struct ED448SecretKey(pub [u8;56]);

pub struct ED448Signature;

impl ED448SecretKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret_key = Scalar::random(&mut rng);
        return Self(secret_key.to_bytes())
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) {

    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return self.0.to_vec()
    }
    pub fn to_byte_array(&self) -> [u8;56] {
        return self.0
    }
    pub fn public_key(&self) -> ED448PublicKey {
        let pk = EdwardsPoint::GENERATOR * &self.to_usable_type();
        let pk_compressed = pk.compress();
        let pk_bytes = pk_compressed.as_bytes();
        return ED448PublicKey(pk_bytes.to_owned())
    }
    pub fn to_usable_type(&self) -> Scalar {
        return Scalar::from_bytes(&self.0)
    }
}