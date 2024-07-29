use libsumatracrypt_rs::digest::*;
use clap::{Arg,Command,Parser,arg};

use crate::read::ReadFile;


use std::ffi::OsString;
use std::path::{Path,PathBuf};

pub fn cli() -> Command {
    Command::new("sumdigest")
        .about("A Command-Line Utility known as SumatraDigest v0.1.0 Written In Memory-Safe Rust Using Zeroize For Hashing Using SHA1, SHA2, SHA3, SHAKE256 at 512-bits, BLAKE2B at variable-digest length, and BLAKE3")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand(
            Command::new("sha1")
            .about("Hashes file and returns hash digest given the SHA1 Hash Function")
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("sha2")
            .about("Hashes file using SHA2 and returns given digest. The given sizes are SHA2-224, SHA2-256, SHA2-384, SHA2-512")
            .arg(
                arg!(--digest <DIGEST>)
                    .value_parser(["28","32","48","64", "224", "256", "384","512"])
                    .num_args(0..=1)
                    .require_equals(true)
                    .default_missing_value("256"),
            )
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true),
        )      
}


pub fn app() {
    let sumdigestapp = cli().get_matches();

    match sumdigestapp.subcommand() {
        Some(("sha1", sub_matches)) => {
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let digest = SumatraSha1::new(bytes);

            println!("{}",digest.to_string().as_str())
        }
        Some(("sha2", sub_matches)) => {
            let digest = sub_matches
                .get_one::<String>("digest")
                .map(|s| s.as_str())
                .expect("defaulted in clap");
            
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            if digest == "256" || digest == "32" {
                let digest = SumatraSha2::sha256(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraSha2::sha224(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraSha2::sha384(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraSha2::sha512(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else {
                println!("[Failure] Digest Length Not Supported or Something Unexpected Happened")
            }

        }
        _ => {
            println!("Print Welcome")
        }
    }
}