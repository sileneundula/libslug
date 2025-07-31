//! # BIP39
//! 
//! This module contains all required operations and functionality to use BIP39, a word generator that uses a seed to produce the secret key of certain algorithms.

use bip39::{Mnemonic, MnemonicType, Language, Seed,ErrorKind};
use serde::{Serialize,Deserialize};

use zeroize::{Zeroize,ZeroizeOnDrop};

/// # SlugMnemonic
/// 
/// The default SlugMnemonic using BIP39
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop, Clone)]
pub struct SlugMnemonic {
    phrase: String,
}

impl SlugMnemonic {
    /// Generate a new Mnemonic using a certain language and length
    pub fn new(mnemonic_type: MnemonicType, language: Language) -> Self {
        let phrase = Mnemonic::new(mnemonic_type, language).into_phrase();

        return Self {
            phrase: phrase,
        }
    }
    /// From Phrase
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self,ErrorKind> {
        let phrase = Mnemonic::from_phrase(phrase, language)?.into_phrase();

        return Ok(Self {
            phrase: phrase,
        })
    }
    /// To Mnemonic
    pub fn to_mnemonic(&self, language: Language) -> Result<Mnemonic,ErrorKind> {
        let mnemonic = Mnemonic::from_phrase(&self.phrase, language)?;

        return Ok(mnemonic)
    }
    /// To Seed Using Password (requires Language to be known)
    pub fn to_seed(&self, pass: &str, language: Language) -> Result<Vec<u8>,ErrorKind> {
        let mnemonic = self.to_mnemonic(language)?;
        let seed = Seed::new(&mnemonic, pass);
        return Ok(seed.as_bytes().to_vec())
    }
}