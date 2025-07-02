pub trait SlugMessageTrait {
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_string(&self) -> String;
    fn from_string(&self, s: &str) -> Self;
}

pub trait SlugEncoding {
    // Bytes
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]);
    
    // Hex
    fn to_hex(&self, bytes: &[u8]);
    fn from_hex(&self, s_hex: &str);

    // Base32
    fn to_base32(&self, bytes: &[u8]);
    fn from_base32(&self, bytes: &[u8]);

    // Base58
    fn to_base58(&self, bytes: &[u8]);
    fn from_base58(&self, s_bs58: &str);

    // Base64
    fn to_base64(&self, bytes: &[u8]);
    fn from_base64(&self, s_bs64: &str);
}