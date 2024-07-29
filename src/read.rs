use std::fs;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;

pub struct ReadFile;

impl ReadFile {
    pub fn new<T: AsRef<Path>>(path: T) -> Vec<u8> {
        let does_file_exist = path.as_ref().exists();
        
        let fbuffer = fs::read(path).expect("failed to open file");

        return fbuffer
    }
}

