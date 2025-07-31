use libslug::slugcrypt::internals::encrypt::chacha20::{XChaCha20Encrypt,EncryptionCipherText,EncryptionKey,EncryptionNonce};

#[test]
fn encrypt() {
    // Generate Key
    let key = EncryptionKey::generate();

    let key_hex = key.to_hex().unwrap();

    let data = "this UTF-8 message is being encrypted via XCHACHA20-POLY1305";
    
    // Encrypt Data
    let (ciphertext,nonce) = XChaCha20Encrypt::encrypt(key, data).unwrap();

    let message = XChaCha20Encrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), nonce, ciphertext).unwrap();

    assert_eq!(String::from_utf8(message).unwrap(),data);
}


#[should_panic]
#[test]
fn encrypt_fail_wrong_message() {
    let key = EncryptionKey::generate();

    let key_hex = key.to_hex().unwrap();

    let data = "this UTF-8 message is being encrypted via XCHACHA20-POLY1305";
    let wrong_message = "this is the wrong message";

    // Encrypt Data
    let (ciphertext,nonce) = XChaCha20Encrypt::encrypt(key, data).unwrap();

    let message = XChaCha20Encrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), nonce, ciphertext).unwrap();

    assert_eq!(String::from_utf8(message).unwrap(),wrong_message);
}

#[should_panic]
#[test]
fn encrypt_wrong_key() {
    // Generate Key
    let key = EncryptionKey::generate();
    let key_2 = EncryptionKey::generate();

    let key_hex = key_2.to_hex().unwrap();
    
    let data = "this UTF-8 message is being encrypted via XCHACHA20-POLY1305";
        
    // Encrypt Data
    let (ciphertext,nonce) = XChaCha20Encrypt::encrypt(key, data).unwrap();
    
    let message = XChaCha20Encrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), nonce, ciphertext).unwrap();
    
    assert_eq!(String::from_utf8(message).unwrap(),data);
}

#[should_panic]
#[test]
fn encrypt_wrong_nonce() {
        // Generate Key
        let key = EncryptionKey::generate();

        let key_hex = key.to_hex().unwrap();
    
        let data = "this UTF-8 message is being encrypted via XCHACHA20-POLY1305";
        
        // Encrypt Data
        let (ciphertext,nonce) = XChaCha20Encrypt::encrypt(key, data).unwrap();
        let (ciphertext_2, nonce_2) = XChaCha20Encrypt::encrypt(EncryptionKey::from_hex(&key_hex).unwrap(), data).unwrap();
    
        let message = XChaCha20Encrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), nonce_2, ciphertext).unwrap();
    
        assert_eq!(String::from_utf8(message).unwrap(),data);
}