use libslug::slugcrypt::internals::signature::schnorr::{SchnorrPublicKey,SchnorrSecretKey,SchnorrSignature,SchnorrIO,SchnorrPreout,SchnorrVRFProof};

fn main() {
    let sk = SchnorrSecretKey::generate();
    let pk = sk.public_key().unwrap();
    let message = "This is a message";
    let context = "SigningContext";

    let output: (SchnorrIO, SchnorrVRFProof, SchnorrPreout) = sk.vrf(message, context);

    println!("Randomness: {:?}", output.0);
    let last_verify = pk.verify_vrf(output.2, output.0, output.1, context, message);

    let x = last_verify.unwrap();

    println!("Randomness: {:?}", x.0);
}