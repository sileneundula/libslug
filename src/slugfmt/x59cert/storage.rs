use std::collections::HashMap;

type local_key_id = String;
type local_keyring_checksum = String;

/// # KeyRingChecksum
/// 
/// Checks for changes in the key ring.
pub struct KeyRingChecksum {
    pub checksum: String,
}


pub struct KeyRing {
    pub keys: HashMap<local_key_id, 
}