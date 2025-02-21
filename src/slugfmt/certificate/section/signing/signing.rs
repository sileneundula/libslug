use super::basics::SigningAlgorithms;


/// # Signing Section
/// 
/// Algorithm is chosen using an enum.
/// 
/// Public Key is UPPER-HEX ENCODED.
/// 
/// Fingerprint is 6-bytes.


pub struct Signing {
    alg: SigningAlgorithms,
    
    pk: String,
    fingerprint: String, // Fingerprint (0xFFFFFFFFFFFF)

}