use crate::constants::OPEN;
use crate::constants::CLOSE;
use crate::constants::*;

use crate::errors::Errors;

pub struct X59Label {
    pub pieces: Vec<String>,
    pub attribute: Option<String>,
}

impl X59Label {
    pub fn new() -> Self {
        return Self {
            pieces: Vec::new(),
            attribute: None,
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

#[test]
fn label_test() {
    let x = X59Label {
        pieces: vec![String::from("libslug"),String::from("shulginsigning"),String::from("v1")],
        attribute: None,
    };
    let output = x.as_label();

    println!("{}",output)
}