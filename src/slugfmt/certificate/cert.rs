/// X59CERT
pub const X59CERTTYPE: &str = "X59CERT";

use serde::{Serialize, Deserialize};
use zeroize::Zeroize;


use super::required_info::RequiredInfo;
use crate::slugfmt::certificate::section::signing::signing::Signing;

pub struct CertType(pub String);

pub struct X59Certificate {
    pub cert: CertType,
    pub required: RequiredInfo,

    // CodeSigning
    pub signing: Option<Signing>,
}

