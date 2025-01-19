use bip39::{Mnemonic, MnemonicType, Language, Seed,ErrorKind};
use serde::{Serialize,Deserialize};

use zeroize::{Zeroize,ZeroizeOnDrop};

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct SlugMnemonic {
    phrase: String,
}

impl SlugMnemonic {
    pub fn new(mnemonic_type: MnemonicType, language: Language) -> Self {
        let phrase = Mnemonic::new(mnemonic_type, language).into_phrase();

        return Self {
            phrase: phrase,
        }
    }
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self,ErrorKind> {
        let phrase = Mnemonic::from_phrase(phrase, language)?.into_phrase();

        return Ok(Self {
            phrase: phrase,
        })
    }
    pub fn to_mnemonic(&self, language: Language) -> Result<Mnemonic,ErrorKind> {
        let mnemonic = Mnemonic::from_phrase(&self.phrase, language)?;

        return Ok(mnemonic)
    }
    pub fn to_seed(&self, pass: &str, language: Language) -> Result<Vec<u8>,ErrorKind> {
        let mnemonic = self.to_mnemonic(language)?;
        let seed = Seed::new(&mnemonic, pass);
        return Ok(seed.as_bytes().to_vec())
    }
}