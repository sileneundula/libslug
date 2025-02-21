pub struct X59Sections {
    sections: Vec<X59SectionsType>
}

pub enum X59SectionsType {
    Signing,
    CodeSigning,
    Encryption,
    Signature,
    
    // X59Registar
    X59Registar,
    X59EncryptionVerification,
    Metadata, // Metadata
    CertWatch,
    
    // Security
    StrictRestrictions,

}