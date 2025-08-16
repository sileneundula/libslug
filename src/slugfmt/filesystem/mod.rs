use std::path::{Path,PathBuf};
use std::fs;

pub const SLUGENCRYPT: &str = ".slugcrypt";

pub struct SlugLocation {
    root_folder: PathBuf,
}

impl SlugLocation {
    pub fn new() {
        let mut home = dirs::home_dir().unwrap();
        home.push(Path::new(SLUGENCRYPT));

        return SlugLocation {
            root_folder: home,
        }
    }
    pub fn init(&self) {
        fs::create_dir(self.root_folder)
    }
}