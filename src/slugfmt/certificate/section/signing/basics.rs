pub enum SigningAlgorithms {
    ED25519,
    SPHINCS_PLUS,
    SlugSchnorr,
    SlugHybrid(u8),
}