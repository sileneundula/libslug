use libslug::slugcrypt::internals::digest::blake2::{SlugBlake2bHasher,SlugBlake2sHasher};
use libslug::slugcrypt::internals::digest::digest::SlugDigest;

fn main() {
    let bytes = SlugBlake2bHasher::new(64usize).update("Hello, world!");
    let digest = SlugDigest::from_bytes(&bytes).unwrap();
    println!("Blake2b: {}", digest.digest());

    let bytes = SlugBlake2sHasher::new(32usize).update("Hello, world!");
    let digest = SlugDigest::from_bytes(&bytes).unwrap();
    println!("Blake2s: {}", digest.digest());

}