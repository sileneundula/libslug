/// X59CERT
pub const X59CERTTYPE: &str = "X59CERT";


use super::required_info::RequiredInfo;
use super::section::signing::signing::Signing;

pub struct CertType(pub String);

pub struct X59Certificate {
    cert: CertType,
    required: RequiredInfo,

    // CodeSigning
    signing: Option<Signing>,
}

