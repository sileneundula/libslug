/// # Message
/// 
/// The **Message Module** contains all methods used for messages sent and received. They are contained in a vector allocated on the heap with **zeroize support**. The message supports an encoding type which reveals the data input to the message. All messages are encoded as UTF-8 bringing modern encoding to cryptography. This means you can encrypt emojis and other languages while having the safety benefits. There is also support for subtle-encoding, encoding the data as constant-time.

use std::str::{self, Utf8Error};
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use std::fmt;

/// # Message Type
/// 
/// An allocated vector of bytes used as the message type. Implements a UTF-8 display method for displaying characters and multiple other methods. Zeroize by default.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq,Zeroize,ZeroizeOnDrop)]
pub struct Message {
    message: Vec<u8>,
}

impl Message {
    pub fn new<T: AsRef<[u8]>>(msg: T) -> Self {
        Self {
            message: msg.as_ref().to_vec(),
        }
    }
    pub fn message(&self) -> Result<&str,Utf8Error> {
        str::from_utf8(&self.message)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.message
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.message.clone()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{}", self.message().expect("[ERROR] Invalid UTF-8"))
    } 
}