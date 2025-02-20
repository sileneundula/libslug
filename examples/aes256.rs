use libslug::slugcrypt::internals::encrypt::aes256::*;

fn main() {
    let key = EncryptionKey::generate();

    let data = b"Hello, world!";

    let encrypted = EncryptAES256::encrypt(key.clone(), data).unwrap();
    let decrypted = DecryptAES256::decrypt(key.clone(), encrypted.1, encrypted.0).unwrap();

    assert_eq!(data.to_vec(), decrypted);
}