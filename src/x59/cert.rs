pub struct X59Cert {
    pub version: u8,
    pub serial_number: u64,
    pub signature_algorithm: String,
    pub issuer: String,
    pub validity: Validity,
    pub subject: String,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id: Option<Vec<u8>>,
    pub subject_unique_id: Option<Vec<u8>>,
    pub extensions: Option<Vec<Extension>>,
}