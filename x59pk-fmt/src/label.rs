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
/// ## Example Code
/// 
/// ### Example
/// 
/// ```rust
/// use x59_fmt::prelude::X59Label;
/// 
/// fn main() {
///     // [example/path/parsed/extension]
///     let _label = X59Label::from_str("example/path/parsed/extension", None);
/// 
///     // [(!algorithm)example/path/parsed/extension] using `Source`
///     let label_with_attribute = X59Label::from_str("example/path/parsed/extension","algorithm")
/// 
///     // Outputs to a String
///     let output = label_with_attribute.into_string();
/// }
/// 
/// ```
/// 
/// ### Mutable Example
/// 
/// ```rust
/// 
/// use x59_fmt::prelude::X59Label;
/// 
/// fn main() {
///     // Generates New X59 Label
///     let mut label: X59Label = X59Label::new();
/// 
///     // Adds Pieces For Path of X59Label (`[test/example/path]<DATA>`)
///     label.add_pieces(vec!["test","example","path"]);
/// 
///     // Outputs into a string
///     let output: String = label.as_source_label();
/// }
/// 
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Label {
    pub pieces: Vec<String>,
    pub attribute: String,
}

/// # X59 Source (`@`)
/// 
/// The Source Parser. Defaults to X59 System and ecosystem.
/// 
/// ## Features
/// 
/// - Git-integration
/// 
/// - URL
/// 
/// - Registries
/// 
/// ## Example
/// 
/// `@git:<user>`
/// 
/// `@url:<url>`
/// 
/// `@source:<source_id>`
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Source {
    source: String,
    parser_protocol: u16,
    
    communication_protocol: u8,
    provider: String,
}

/// # Type of Data (`#`)
/// 
/// `#pk`
/// 
/// `#peer`
/// 
/// 
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Type {
    lib: TypeLibrary,
    _type: String,
}

/// # X59 Constraint System
/// 
/// 
pub struct X59Constraints {
    constraint: String,
}

impl Default for X59Type {
    fn default() -> Self {
        X59Type {
            lib: TypeLibrary::default(),
            _type: String::from("Raw"),
        }
    }
}

impl fmt::Display for X59Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Library: {}",&self.lib)
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub enum TypeLibrary {
    X59std(u16), // X59std lib (assumed as default)
    
    Git(String),
    URL(String),
    Other(String),
}

/*
impl fmt::Display for TypeLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if Self::X59std(0u16) == true {
            write!(f, "X59 Standard Library (Revision: 0x00)")
        }
        else if Self::X59std(1) == true {
            write!(f, "X59 Standard Library (Revision: 0x01)")
        }
        else if Self::X59std(0xFFu16) == true {
            write!(f, "X59 Standard Library Nightly (Revision 0xFF)")
        }
        else if Self::X59std(2) == true {
            write!(f, "X59 Standard Library Slim (Revision 0x02")
        }
        else {
            write!(f, "Unknown Library")
        }

        if self::TypeLibrary::X59std(0u16) {
            write!(f, "X59 Standard Library (Revision: 0x00)")
        }
    }
}
    */

impl Default for TypeLibrary {
    fn default() -> Self {
        TypeLibrary::X59std(0u16)
    }
}

impl X59Source {
    /// # Parser Source
    pub fn new<T: AsRef<str>>(source: T) -> Self {
        return Self {
            source: source.as_ref().to_string(),
            provider: 
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
    /// # Into String
    /// 
    /// Wrapper around `as_source_label` for ease of access
    pub fn into_string(&self) -> String {
        return self.as_source_label()
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
            attribute: attribute.as_ref().to_string(),
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
    pub fn add_attribute<T: AsRef<str>>(&mut self, attribute: T) {
        self.attribute = attribute.as_ref().to_string();
    }
    pub fn new_with_configured<T: AsRef<str>>(pieces: Vec<T>, attribute: Option<String>) {

    }
    pub fn as_label(&self) -> String {
        let mut output: String = String::new();

        output.push_str(OPEN);

        let mut i = 0usize;
        let mut length = self.pieces.len() - 1;
        
        if self.attribute == "" || self.attribute == " " {
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
            let attribute = Self::process_attribute(&self).expect("Failure In Attribute Assignment Due To No Attribute");

            // Push (!..)
            output.push_str(&attribute);

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
    fn process_attribute(&self) -> Result<String,Errors> {
        let mut output: String = String::new();

        if self.attribute != "" || self.attribute != " " {
            output.push_str(OPEN_PAR); // (
            output.push_str(ATTRIBUTE_VALUE); // !

            output.push_str(&self.attribute);
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