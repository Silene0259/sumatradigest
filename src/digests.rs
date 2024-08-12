use libsumatracrypt_rs::digest::*;
use clap::{Arg,Command,Parser,arg,ArgAction};

use crate::read::ReadFile;


use std::ffi::OsString;
use std::path::{Path,PathBuf};
use std::io::prelude::*;
use std::fs::File;

pub enum HASH_TYPES {
    SHA1,
    SHAKE256,
    BLAKE3,

    SHA256,
    SHA384,
    SHA512,
    SHA224,
    
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    
    BLAKE2B224,
    BLAKE2B256,
    BLAKE2B384,
    BLAKE2B512,
    BLAKE2BVAR,

    CHECKSUM,

}



pub fn cli() -> Command {
    Command::new("sumdigest")
        .about("A Command-Line Utility known as SumatraDigest v0.1.0 Written In Memory-Safe Rust Using Zeroize For Hashing Using SHA1, SHA2, SHA3, SHAKE256 at 512-bits, BLAKE2B at variable-digest length, and BLAKE3")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand(
            Command::new("sha1")
            .about("Hashes file and returns hash digest given the SHA1 Hash Function")
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            
        )
        .subcommand(
            Command::new("sha2")
            .about("Hashes file using SHA2 and returns given digest. The given sizes are SHA2-224, SHA2-256, SHA2-384, SHA2-512")
            .arg(
                arg!(--digest <DIGEST>)
                    .value_parser(["28","32","48","64", "224", "256", "384","512"])
                    .num_args(0..=1)
                    .require_equals(true)
                    .default_missing_value("32")
                    .short('d')
            )
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
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
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
        )
        .subcommand(
            Command::new("blake3")
            .about("Hashes files using the BLAKE3 hash function and returns given digest.")
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            
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
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
        )
        .subcommand(
            Command::new("shake256")
            .about("Hashes file using the SHAKE256 hash function and returns given digest. The size is 512-bits")
            .arg(arg!(path: [PATH]))
            .arg_required_else_help(true)
            .arg(
                arg!(-c --checksum <CHECKSUM>)
                .short('c')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            .arg(
                arg!(-w --write <WRITE>)
                .short('w')
                .num_args(0)
                .action(ArgAction::SetTrue)
            )
            

        )

}


pub fn app() {
    let sumdigestapp = cli().get_matches();

    match sumdigestapp.subcommand() {
        Some(("sha1", sub_matches)) => {
            pub const HASH_TYPE: &str = "SHA1";
            
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let digest = SumatraSha1::new(&bytes);

            let mut ck = false;

            ck = sub_matches
            .get_flag("checksum");


            let mut writ = false;
            writ = sub_matches.get_flag("write");

            if ck == true {
                let checksum = checksum(&bytes);
                println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str());
            }
            else {
                println!("{}",digest.to_string().as_str());
            }

            if writ == true {
                let checksum = checksum(&bytes);
                digest_write_to_file(digest, checksum, HASH_TYPES::SHA1);
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

            // ====CHECKSUM====
            let mut ck = false;

            ck = sub_matches
            .get_flag("checksum");

            let mut writ = false;
            writ = sub_matches.get_flag("write");

            if digest == "256" || digest == "32" {
                pub const HASH_TYPE: &str = "SHA256";
                let digest = SumatraSha2::sha256(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA256);
                }
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraSha2::sha224(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA224);
                }
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraSha2::sha384(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA384);
                }
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraSha2::sha512(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA512);
                }
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


            //====CHECKSUM====
            let mut ck = false;

            ck = sub_matches
            .get_flag("checksum");

            let mut writ = false;
            writ = sub_matches.get_flag("write");

            if digest == "256" || digest == "32" {
                let digest = SumatraSha3::sha3_256(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA3_256);
                }
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraSha3::sha3_224(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA3_224);
                }
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraSha3::sha3_384(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA3_384);
                }
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraSha3::sha3_512(&bytes);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::SHA3_512);
                }
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
            let path_unwrapped = path.expect("Failed To Get Path For BLAKE2B");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let key = vec![];

            //====CHECKSUM====
            let mut ck = false;

            ck = sub_matches
            .get_flag("checksum");

            let mut writ = false;
            writ = sub_matches.get_flag("write");

            if digest == "256" || digest == "32" {
                let digest = SumatraBlake2b::new(&bytes, &key, 32usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2B256);
                }
            }
            else if digest == "224" || digest == "28" {
                let digest = SumatraBlake2b::new(&bytes, &key, 28usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2B224);
                }
            }
            else if digest == "384" || digest == "48" {
                let digest = SumatraBlake2b::new(&bytes, &key, 48usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2B384);
                }
            }
            else if digest == "512" || digest == "64" {
                let digest = SumatraBlake2b::new(&bytes, &key, 32usize);

                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2B512);
                }
            }
            else if digest == "4" {
                let digest = SumatraBlake2b::new(&bytes, &key, 4usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "6" {
                let digest = SumatraBlake2b::new(&bytes, &key, 6usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "8" {
                let digest = SumatraBlake2b::new(&bytes, &key, 8usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "12" || digest == "96" {
                let digest = SumatraBlake2b::new(&bytes, &key, 12usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "16" || digest == "128" {
                let digest = SumatraBlake2b::new(&bytes, &key, 16usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "20" || digest == "160" {
                let digest = SumatraBlake2b::new(&bytes, &key, 20usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "24" || digest == "192" {
                let digest = SumatraBlake2b::new(&bytes, &key, 24usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "36" || digest == "288" {
                let digest = SumatraBlake2b::new(&bytes, &key, 36usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "40" || digest == "320" {
                let digest = SumatraBlake2b::new(&bytes, &key, 40usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "44" || digest == "352" {
                let digest = SumatraBlake2b::new(&bytes, &key, 44usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "52" || digest == "416" {
                let digest = SumatraBlake2b::new(&bytes, &key, 52usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "56" || digest == "448" {
                let digest = SumatraBlake2b::new(&bytes, &key, 56usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
            }
            else if digest == "60" || digest == "480" {
                let digest = SumatraBlake2b::new(&bytes, &key, 60usize);
                if ck == true {
                    let checksum = checksum(&bytes);
                    println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
                }
                else {
                    println!("{}",digest.to_string().as_str())
                }
                if writ == true {
                    let checksum = checksum(&bytes);
                    digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE2BVAR);
                }
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

            // ===Checksum===
            let mut ck = false;

            let mut writ = false;

            ck = sub_matches
            .get_flag("checksum");

            writ = sub_matches.get_flag("write");

            let digest = SumatraBlake3::new(&bytes);

            if ck == true {
                let checksum = checksum(&bytes);
                println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str())
            }
            else {
                println!("{}",digest.to_string().as_str())
            }

            if writ == true {
                let checksum = checksum(&bytes);
                digest_write_to_file(digest, checksum, HASH_TYPES::BLAKE3);
            }

        }
        Some(("shake256", sub_matches)) => {
            let mut path = sub_matches.get_one::<String>("path").map(|s| s.as_str());
            let path_unwrapped = path.expect("Failed To Get Path For SHA1");
            let current_path = Path::new(path_unwrapped);
            let bytes = ReadFile::new(current_path);

            let digest = SumatraShake256::new(&bytes);

            let mut ck = false;

            let mut writ = false;

            ck = sub_matches
            .get_flag("checksum");

            writ = sub_matches.get_flag("write");

            if ck == true {
                let checksum = checksum(&bytes);
                println!("{} ({})",digest.to_string().as_str(),checksum.to_string().as_str());
            }
            else {
                println!("{}",digest.to_string().as_str())
            }
            if writ == true {
                let checksum = checksum(&bytes);
                digest_write_to_file(digest, checksum, HASH_TYPES::SHAKE256);
            }

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

pub fn digest_write_to_file(digest: SumatraDigest, checksum: SumatraDigest, hash_type: HASH_TYPES) -> std::io::Result<()> {
    let mut checksum_filename = checksum.to_string();
    checksum_filename.push_str(".sum");

    let final_digest = digest.to_string();


    //let mut final_path = path;
    //final_path.push(checksum_filename);

    let hash = match hash_type {
        HASH_TYPES::SHA1 => "SHA1: ",
        HASH_TYPES::SHAKE256 => "SHAKE256: ",
        HASH_TYPES::BLAKE3 => "BLAKE3: ",
        
        HASH_TYPES::CHECKSUM => "BLAKE2B CHECKSUM: ",

        HASH_TYPES::SHA224 => "SHA224: ",
        HASH_TYPES::SHA256 => "SHA256: ",
        HASH_TYPES::SHA384 => "SHA384: ",
        HASH_TYPES::SHA512 => "SHA512: ",
        
        HASH_TYPES::SHA3_224 => "SHA3-224: ",
        HASH_TYPES::SHA3_256 => "SHA3-256: ",
        HASH_TYPES::SHA3_384 => "SHA3-384: ",
        HASH_TYPES::SHA3_512 => "SHA3-512: ",

        HASH_TYPES::BLAKE2B224 => "BLAKE2B-224: ",
        HASH_TYPES::BLAKE2B256 => "BLAKE2B-256: ",
        HASH_TYPES::BLAKE2B384 => "BLAKE2B-384: ",
        HASH_TYPES::BLAKE2B512 => "BLAKE2B-512: ",

        HASH_TYPES::BLAKE2BVAR => "BLAKE2B-VARIABLE-DIGEST-LEN: ",
    };

    
    let mut final_data_for_file = String::new();

    final_data_for_file.push_str(hash);
    final_data_for_file.push_str(final_digest.as_str());
    
    
    final_data_for_file.push_str(" (");
    final_data_for_file.push_str(&checksum.to_string());
    final_data_for_file.push_str(")");

    
    let mut file = File::create(checksum_filename)?;
    file.write_all(final_digest.as_bytes())?;
    Ok(())
}