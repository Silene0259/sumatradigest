use libsumatracrypt_rs::digest::*;
use clap::{Arg,Command,Parser,arg,ArgAction};

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
            .arg(
                arg!(-ck --checksum <CHECKSUM>)
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
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
                    .default_missing_value("256")
                    .short('d')
            )
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("sha3")
            .about("Hashes files using the SHA3 function and returns given digest. The given sizes are SHA3-223, SHA3-256, SHA3-384, SHA3-512")
            .arg(
                arg!(--digest <DIGEST>)
                .value_parser(["28","32","48","64","224","256","384","512"])
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("32")
                .short('d')
            )
            .arg(arg!(path: [PATH]))
        )
        .subcommand(
            Command::new("blake3")
            .about("Hashes files using the BLAKE3 hash function and returns given digest.")
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("blake2b")
            .about("Hashes files using the blake2b function and returns given digest. The given sizes are SHA3-223, SHA3-256, SHA3-384, SHA3-512")
            .arg(
                arg!(--digest <DIGEST>)
                .value_parser(["4","6","8","12","16","20","24","28","32","36","40","44","48","52","56","60","64","96","128","160","192","224","256","288","320","352","384","416","448","480","512"])
                .num_args(0..=1)
                .require_equals(true)
                .default_missing_value("256")
                .short('d')
                
            )
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("shake256")
            .about("Hashes file using the SHAKE256 hash function and returns given digest. The size is 512-bits")
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

            let digest = SumatraSha1::new(&bytes);

            let mut ck = false;

            ck = sub_matches
            .get_flag("checksum");

            if ck == true {
                let checksum = checksum(&bytes);
                println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str());
            }
            else {
                println!("{}",digest.to_string().as_str());
            }
        }
        Some(("sha2", sub_matches)) => {
            let digest = sub_matches
                .get_one::<String>("digest")
                .map(|s| s.as_str())
                .unwrap_or("32");
            
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA2");
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
        Some(("sha3", sub_matches)) => {
            let digest = sub_matches
                .get_one::<String>("digest")
                .map(|s| s.as_str())
                .unwrap_or("32");
            
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA3");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            if digest == "256" || digest == "32" {
                let digest = SumatraSha3::sha3_256(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraSha3::sha3_224(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraSha3::sha3_384(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraSha3::sha3_512(bytes);
                println!("{}",digest.to_string().as_str())
            }
            else {
                println!("[Failure] Digest Length Not Supported or Something Unexpected Happened")
            }

        }
        Some(("blake2b", sub_matches)) => {
            let digest = sub_matches
                .get_one::<String>("digest")
                .map(|s| s.as_str())
                .unwrap_or("32");
            
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let key = vec![];

            if digest == "256" || digest == "32" {
                let digest = SumatraBlake2b::new(bytes, key, 32usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraBlake2b::new(bytes, key, 28usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraBlake2b::new(bytes, key, 48usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraBlake2b::new(bytes, key, 32usize);

                println!("{}",digest.to_string().as_str())
            }
            else if digest == "4" {
                let digest = SumatraBlake2b::new(bytes, key, 4usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "6" {
                let digest = SumatraBlake2b::new(bytes, key, 6usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "8" {
                let digest = SumatraBlake2b::new(bytes, key, 8usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "12" || digest == "96" {
                let digest = SumatraBlake2b::new(bytes, key, 12usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "16" || digest == "128" {
                let digest = SumatraBlake2b::new(bytes, key, 16usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "20" || digest == "160" {
                let digest = SumatraBlake2b::new(bytes, key, 20usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "24" || digest == "192" {
                let digest = SumatraBlake2b::new(bytes, key, 24usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "36" || digest == "288" {
                let digest = SumatraBlake2b::new(bytes, key, 36usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "40" || digest == "320" {
                let digest = SumatraBlake2b::new(bytes, key, 40usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "44" || digest == "352" {
                let digest = SumatraBlake2b::new(bytes, key, 44usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "52" || digest == "416" {
                let digest = SumatraBlake2b::new(bytes, key, 52usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "56" || digest == "448" {
                let digest = SumatraBlake2b::new(bytes, key, 56usize);
                println!("{}",digest.to_string().as_str())
            }
            else if digest == "60" || digest == "480" {
                let digest = SumatraBlake2b::new(bytes, key, 60usize);
                println!("{}",digest.to_string().as_str())
            }
            else {
                println!("[Failure] Digest Length Not Supported or Something Unexpected Happened")
            }

        }
        Some(("blake3", sub_matches)) => {
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let digest = SumatraBlake3::new(bytes);

            println!("{}",digest.to_string().as_str())
        }
        Some(("shake256", sub_matches)) => {
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let digest = SumatraShake256::new(bytes);

            println!("{}",digest.to_string().as_str())
        }
        _ => {
            println!("Print Welcome")
        }
    }
}

pub fn checksum(bytes: &[u8]) -> SumatraDigest {
    let key = vec![];
    return SumatraBlake2b::new(bytes, &key, 8usize)
}