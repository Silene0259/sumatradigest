# SumatraDigest

## Description

An easy to use hashing tool with security in mind that supports extra security measures (special checksums). It uses **pure-rust**, aims to be **easy to use**, and **supports various features** like checksums (`-c`) and writing to file (`-w`). It also implemnts **zeroize** for privacy. There are variable digest lengths for certain hash functions that use the argument `d=<bits>` or `d=<bytes>`.

* SHA1
* SHA2 (224,256,384,512)
* SHA3 (224,256,384,512)
* BLAKE2B (variable digest)
* BLAKE3
* SHAKE256 (512-bits).

## How To Install

### From Cargo

1. Install Cargo
2. `cargo install sumatradigest`

## How To Build From Source (Easy)

1. Have Rust installed. Simple and Easy to install. Install instructions are [here](https://www.rust-lang.org/tools/install).
2. Clone Repository
3. Build from source by typing `cargo build --release`

## Usage

If using executable, use the following

`./sumatradigest <command> [Path]`

If installed via cargo, you can just use sumatradigest.

`sumatradigest`

### Help

`sumatradigest help`

### Get Hash

`sumatradigest <hasher> [Path]`

#### Examples

##### SHA1

`sumatadigest sha1 [Path]`

`sumatradigest sha1 ExampleFile.txt`

##### SHA2

Get SHA224 Digest

`sumatradigest sha2 -d=224 ExampleFile.txt`

Get SHA256 Digest

`sumatradigest sha2 ExampleFile.txt`

Get SHA512 digest

`sumatradigest sha2 -d=512 ExampleFile.txt`

### Get Hash With Blake2B Checksum (Extra Security and for quick error checking)

This function returns a blake2b checksum of 8-bytes.

`sumatradigest <hasher> -c [Path]`

#### Examples

### Get Hash and Write to file

This function writes it to a i

`sumatradigest <hasher> -w [Path]`

### Get Hash, Write To File, and Checksum

This function writes to a file and prints the checksum.

`sumatradigest <hasher> -c -w [Path]`

### Get Variable Digest

### Hashers

This is the list of hashers:

* SHA1
* SHA2
* SHA3
* SHAKE256
* BLAKE2B
* BLAKE3
