//! # X59 Data
//! 
//! ## Author
//! 
//! Joseph P. Tortorelli (Silene/0x20CB)
//! 
//! ## Features
//! 
//! - [X] X59-fmt
//!     - [X] X59Label (`[..]`)
//!         - [X] Attribute (`(!..)`)
//!         - [ ] Checksum
//!     - [ ] X59ParserSource (`@`)
//!     - [ ] X59DataType (`#`)
//!         - [ ] Source
//! 
//! TODO:
//! 
//! - [X] X59Label
//!     - [X] Display
//!     - [ ]
//! - [X] X59Source (@)
//!     - [ ] Source
//! - [X] X59Type (#)
//!     - [ ] Source

use crate::constants::OPEN;
use crate::constants::CLOSE;
use crate::constants::*;

use crate::errors::Errors;

use std::fmt;

/// # X59 Label
/// 
/// ## Description
/// 
/// The core component of `X59-fmt`, an *X59Label* functions to add context to values, including structured data in extensions.
/// 
/// X59Label consists of two data values:
/// 
/// 1. **Pieces** (UTF-8 String Pieces In A Vector)
/// 2. **Attribute** (An attribute data value that adds context using the `X59ParserSource`)
/// 
/// ## 
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Label {
    pub pieces: Vec<String>,
    pub attribute: Option<String>,
}

/// # X59 Source
/// 
/// The Source Parser. Defaults to X59 System.
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Source {
    source: String,
}

/// # Type of Data
/// 
/// `#pk`
/// 
/// `#peer`
/// 
/// 
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Type {
    _type: String,
}

impl X59Source {
    /// # Parser Source
    pub fn new<T: AsRef<str>>(source: T) -> Self {
        return Self {
            source: source.as_ref().to_string()
        }
    }
    pub fn as_source_label(&self) -> String {
        let mut output: String = String::new();

        output.push_str(OPEN);
        output.push_str(SOURCE_SYMBOL);
        output.push_str(&self.source);
        output.push_str(CLOSE);

        return output
    }
}

impl Default for X59Source {
    fn default() -> Self {
        return Self {
            source: String::from("X59System")
        }
    }
}

impl X59Label {
    pub fn new() -> Self {
        return Self {
            pieces: Vec::new(),
            attribute: None,
        }
    }
    pub fn from_str<T: AsRef<str>>(s_path: T, attribute: T) -> Self {
        let x: Vec<&str> = s_path.as_ref().split("/").collect();

        let mut output: Vec<String> = Vec::new();

        for i in x {
            output.push(i.to_owned());
        }

        return Self {
            pieces: output,
            attribute: Some(attribute.as_ref().to_string()),
        }
    }
    /// # Add Piece To X59Label
    /// 
    /// Adds a singular piece to the path of an X59Label
    pub fn add_piece<T: AsRef<str>>(&mut self, piece: T) {
        self.pieces.push(piece.as_ref().to_string())
    }
    /// # Add Pieces To X59Label (Using a Vector)
    /// 
    /// Adds multiple pieces to the path of the X59 Label
    pub fn add_pieces<T: AsRef<str>>(&mut self, pieces: Vec<T>) {
        for x in pieces {
            self.pieces.push(x.as_ref().to_string())
        }
    }
    pub fn new_with_configured<T: AsRef<str>>(pieces: Vec<T>, attribute: Option<String>) {

    }
    pub fn as_label(&self) -> String {
        let mut output: String = String::new();

        output.push_str(OPEN);

        let mut i = 0usize;
        let mut length = self.pieces.len() - 1;
        
        if self.attribute.is_none() {
            for x in &self.pieces {
                output.push_str(x);
                if i < length {
                    output.push_str(DELIMITER);
                    i = i + 1;
                }
                else {
                    output.push_str(CLOSE);
                }
            }
            return output
        }
        else {
            /*
            let attribute = Self::add_attribute(&self).expect("Failure In Attribute Assignment Due To No Attribute");

            for i in self.pieces {

            }

*/
            panic!("Attribute");
        }
        
        
        

    }
    fn add_label_open() {

    }
    /// # Add Attribute
    /// 
    /// Adds an Attribute onto a label
    /// 
    /// ## Format
    /// 
    /// `(!<value>)` where value is some value and inside braces
    fn add_attribute(&self) -> Result<String,Errors> {
        let mut output: String = String::new();

        output.push_str(OPEN_PAR); // (
        output.push_str(ATTRIBUTE_VALUE); // !

        if self.attribute.is_some() == true {
            output.push_str(&self.attribute.clone().unwrap());
            output.push_str(CLOSE_PAR);   
        }
        else {
            return Err(Errors::NoAttributeInLabel)
        }
        return Ok(output)
    }
}

impl fmt::Display for X59Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = self.as_label();
        write!(f, "{}",x)
    }
}


#[test]
fn label_test() {
    let x = X59Label {
        pieces: vec![String::from("libslug"),String::from("shulginsigning"),String::from("v1")],
        attribute: None,
    };
    let output = x.as_label();

    println!("{}",output)
}