use std::path::{Path,PathBuf};
use std::fs;

pub const FOLDER_SLUGCRYPT: &str = ".slugcrypt";

pub struct SlugLocation {
    pub root_folder: PathBuf,
}

impl SlugLocation {
    /// # Create Location Struct
    pub fn new() -> Self {
        let mut home = dirs::home_dir().unwrap();
        home.push(Path::new(FOLDER_SLUGCRYPT));

        return SlugLocation {
            root_folder: home,
        }
    }
    /// # Init Directory
    pub fn init(&self) {
        fs::create_dir(&self.root_folder).unwrap()
    }
}