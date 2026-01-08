use fixedstr::str256;

#[derive(Copy,Clone,Debug,PartialEq,PartialOrd,Hash)]
pub struct OintPublicKey {
    pk: str256,
}

#[derive(Copy,Clone,Debug,PartialEq,PartialOrd,Hash)]
pub struct OintSecretKey {
    sk: str256,
}

#[derive(Copy,Clone,Debug,PartialEq,PartialOrd,Hash)]
pub struct OintInfo {
    alg: str256,
}

pub struct OintPublicKeyV2 {
    pk: String,
}

pub struct OintSecretKeyV2 {
    sk: String,
}

pub struct OintKeypair {
    pkh: OintPublicKey,
    skh: OintSecretKey,
}