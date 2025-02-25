use libslug::slugcrypt::internals::digest::sha2::Sha2Hasher;
use libslug::slugcrypt::internals::digest::digest::SlugDigest;

fn main() {
    let mut hasher = Sha2Hasher::new(384);
    let data = "hello world";
    let bytes = hasher.hash(data.as_bytes());

    let result = SlugDigest::from_bytes(&bytes).unwrap();
    println!("SHA2 (384): {}", result.digest());
}