use libslug::slugcrypt::internals::bip39::SlugMnemonic;

fn main() {
    // Select Language
    let language = bip39::Language::English;
    // Select Number of Words In Phrase
    let length = bip39::MnemonicType::Words24;
    // Select Password
    let password: &str = "This is the password for the Seed";


    // Generate Phrase
    let phrase = SlugMnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English);
    
    
    // Get Seed
    let seed: Vec<u8> = phrase.to_seed(password, language).unwrap();
}