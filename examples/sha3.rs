use libslug::slugcrypt::internals::digest::sha3::Sha3Hasher;
use libslug::slugcrypt::internals::digest::digest::SlugDigest;

fn main() {
    let mut hasher = Sha3Hasher::new(384);
    let data = "hello world";
    let bytes = hasher.update(data.as_bytes());

    let result = SlugDigest::from_bytes(&bytes).unwrap();
    println!("SHA3 (384): {}", result.digest());
}