use super::sections::{X59Sections,X59SectionsType};
use super::registar::{Registar,RegistarTypes};
use super::revocation::{Revocation,RevocationMethods};
use super::extensions::{Extensions,ExtensionTypes};

pub struct RequiredInfo {
    sections: X59Sections,
    
    registar: Registar,
    revocation: Revocation,
    extensions: Extensions,
}