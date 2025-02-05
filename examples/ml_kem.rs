use libslug::slugcrypt::internals::encryption::ml_kem;

fn main() {
    let (pk,sk) = ml_kem::MLKEMSecretKey::generate();
    let (pk_to,sk_to) = ml_kem::MLKEMSecretKey::generate();

    let (ciphertext, shared_secret) = pk_to.encapsulate();

    let shared_secret_decap = sk_to.decapsulate(ciphertext);

    assert_eq!(shared_secret,shared_secret_decap);
}