pub enum SigningAlgorithms {
    ED25519,
    SPHINCS_PLUS,
    SlugHybrid(u8),
}