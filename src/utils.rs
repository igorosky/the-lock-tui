use std::{path::Path, fs::{File, create_dir}, io::{Read, Write}, ops::RangeBounds};

use dialoguer::{Confirm, Password, Input, Select};
use serialize_with_password::{Serialize, Deserialize, serialize_serde_no_pass, serialize_serde, is_encrypted, deserialize_serde, deserialize_serde_no_pass};
use the_lock_lib::{signers_list::SignersList, rsa::{RsaPublicKey, RsaPrivateKey}, asymetric_key::{PrivateKey, PublicKey}, EncryptedFile, directory_content::DirectoryContent, FileOptions};

fn delete_path<P: AsRef<Path>>(path: P) {
    match (path.as_ref().is_file(), path.as_ref().is_dir()) {
        (true, _) => std::fs::remove_file(path).expect("Could't delete file"),
        (_, true) => std::fs::remove_dir_all(path).expect("Could't delete directory"),
        _ => (),
    }
}

#[inline]
pub fn get_number_in_range<T, R: RangeBounds<T>>(prompt: &str, range: R, default: T) -> T 
    where T: std::str::FromStr + std::fmt::Display + PartialEq + PartialOrd, <T as std::str::FromStr>::Err: std::fmt::Debug {
    Input::<String>::new().with_prompt(prompt).default(default.to_string()).validate_with(|v: &String| -> Result<(), String> {
        if let Ok(v) = v.parse::<T>() {
            if range.contains(&v) {
                Ok(())
            }
            else {
                Err(format!("Value out of range"))
            }
        }
        else {
            Err("It's not an number".to_owned())
        }
    }).interact().expect("IO error").parse().expect("Value should be validated")
}

#[inline]
pub fn get_path(prompt: &str) -> String {
    Input::<String>::new().with_prompt(prompt).interact().expect("IO error")
}

#[inline]
fn prepate_path() -> Option<Box<Path>> {
    let target = get_path("File path");
    let path = Path::new(&target);
    if path.exists() {
        if Confirm::new().with_prompt(format!("Path {target} already exists. Delete it?")).interact().expect("IO error") {
            delete_path(path);
        }
        else {
            return None;
        }
    }
    Some(Box::from(path))
}

pub fn save<T: Serialize>(val: &T) -> bool {
    let path = match prepate_path() {
        Some(path) => path,
        None => return false,
    };
    match match Confirm::new().with_prompt("With password?").interact().expect("IO error") {
        true => serialize_serde(
            val,
            Password::new()
                        .with_prompt("Passwrod")
                        .with_confirmation("Repeat password", "Passwords are not the same")
                        .interact()
                        .expect("IO error")
                        .as_bytes()
        ),
        false => serialize_serde_no_pass(val)
    } {
        Ok(data) => {
            match File::create(path) {
                Ok(mut file) => {
                    match file.write_all(&data) {
                        Ok(()) => true,
                        Err(err) => {
                            println_error(&format!("Couldn't save data to file - {}", err));
                            false
                        }
                    }
                }
                Err(err) => {
                    println_error(&format!("Couldn't create a file - {}", err));
                    false
                }
            }
        }
        Err(err) => {
            println_error(&format!("Unexpected error while saving file - {}", err));
            false
        }
    }
}

#[inline]
pub fn check_path(prompt: &str) -> Option<Box<Path>> {
    let src = get_path(prompt);
    let path = Path::new(&src);
    if !path.exists() {
        println_error(&format!("Path {src} does't exists"));
        return None;
    }
    Some(Box::from(path))
}

pub fn read<T: for<'a> Deserialize<'a>>(prompt: &str) -> Option<T> {
    let path = match check_path(prompt) {
        Some(path) => path,
        None => return None,
    };
    if !path.is_file() {
        println_error(&format!("It's is not a file"));
        return None;
    }
    let mut buf = Vec::new();
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            println_error(&format!("Unhandled error while opening file - {err}"));
            return None;
        }
    };
    if let Err(err) = file.read_to_end(&mut buf) {
        println_error(&format!("Unhandled error while reading file - {err}"));
        return None;
    }
    let is_enc = match is_encrypted(&buf) {
        Ok(ans) => ans,
        Err(serialize_with_password::Error::DataIsEmpty) => {
            println!("File is empty");
            return None;
        }
        Err(err) => {
            println_error(&format!("Unexpected error while checking if file is encrypted - {err}"));
            return None;
        }
    };
    match is_enc {
        true => {
            let mut ans = deserialize_serde(
                &buf,
                Password::new()
                            .with_prompt("Password")
                            .interact()
                            .expect("IO error")
                            .as_bytes()
            );
            while let Err(serialize_with_password::Error::WrongPassword) = ans {
                ans = deserialize_serde(
                    &buf,
                    Password::new()
                                .with_prompt("Wrong password")
                                .interact()
                                .expect("IO error")
                                .as_bytes()
                );
                if !Confirm::new().with_prompt("Try again?").default(true).interact().expect("IO error") {
                    return None;
                }
            }
            if let Err(err) = ans.as_ref() {
                println_error(&format!("Unhandled error while deserializing file - {err}"));
            }
            ans.ok()
        }
        false => match deserialize_serde_no_pass(&buf) {
            Ok(ans) => Some(ans),
            Err(err) => {
                println_error(&format!("Unhandled error while deserializing file - {err}"));
                None
            }
        }
    }
}

pub fn create_signers_list() -> Option<SignersList> {
    let path = match prepate_path() {
        Some(path) => path,
        None => return None,
    };
    if let Err(err) = create_dir(path) {
        println_error(&format!("Couldn't create a directory for signers list - {}", err));
        return None;
    }
    SignersList::new(Path::new(&Input::<String>::new().with_prompt("File path").interact().expect("IO error"))).ok()
}

pub fn open_signer_list() -> Option<SignersList> {
    let path = match check_path("Signers list path") {
        Some(path) => path,
        None => return None,
    };
    if !path.is_dir() {
        println_error(&format!("It's is not a directory"));
        return None;
    }
    match SignersList::open(path) {
        Ok(ans) => Some(ans),
        Err(err) => {
            println_error(&format!("Unexpected error while opening a signers list - {err}"));
            None
        }
    }
}

#[inline]
pub fn get_private_key() -> Option<PrivateKey> {
    read::<PrivateKey>("Private key path")
}

pub fn get_public_key() -> Option<PublicKey> {
    match Select::new()
            .items(&[
                "From public key",
                "From private key",
                "Exit",
            ])
            .default(0)
            .with_prompt("Public key source")
            .interact()
            .expect("IO error") {
        0 => read::<PublicKey>("Public key path"),
        1 => read::<PrivateKey>("Private key path").map(|key: PrivateKey| key.get_public_key()),
        _ => None,
    }
}

pub fn get_private_rsa_key() -> Option<RsaPrivateKey> {
    match Select::new()
            .items(&[
                "From RSA private key",
                "From private key",
                "Exit",
            ])
            .default(0)
            .with_prompt("Private RSA key source")
            .interact()
            .expect("IO error") {
        0 => read::<RsaPrivateKey>("Private RSA key path"),
        1 => read::<PrivateKey>("Private key path").map(|key: PrivateKey| key.get_rsa_private_key().to_owned()),
        _ => None,
    }
}

pub fn get_public_rsa_key() -> Option<RsaPublicKey> {
    match Select::new()
            .items(&[
                "From RSA public key",
                "From RSA private key",
                "From private key",
                "From public key",
                "Exit",
            ])
            .default(0)
            .with_prompt("Public RSA key source")
            .interact()
            .expect("IO error") {
        0 => read::<RsaPublicKey>("Public RSA key path"),
        1 => read::<RsaPrivateKey>("Private RSA key path").map(|key: RsaPrivateKey| key.to_public_key()),
        2 => read::<PrivateKey>("Private key path").map(|key: PrivateKey| key.get_rsa_public_key()),
        3 => read::<PublicKey>("Public key path").map(|key: PublicKey| key.get_rsa_public_key().to_owned()),
        _ => None,
    }
}

#[inline]
pub fn create_file() -> Option<File> {
    File::create(prepate_path()?).ok()
}

#[inline]
pub fn create_file_with_default(value: String) -> Option<File> {
    File::create({
        let target = Input::<String>::new().with_prompt("File path").default(value).interact().expect("IO error");
        let path = Path::new(&target);
        if path.exists() {
            if Confirm::new().with_prompt(format!("Path {target} already exists. Delete it?")).interact().expect("IO error") {
                delete_path(path);
            }
            else {
                return None;
            }
        }
        Box::from(path)
    }).ok()
}

#[inline]
pub fn open_file(prompt: &str) -> Option<File> {
    File::open(check_path(prompt)?).ok()
}

pub fn create_encrypted_file() -> Option<EncryptedFile> {
    match EncryptedFile::new(match prepate_path() {
        Some(path) => path,
        None => return None,
    }) {
        Ok(ef) => Some(ef),
        Err(err) => {
            println_error(&format!("Unhandled error while trying to create encrypted file - {err}"));
            None
        }
    }
}

pub fn open_encrypted_file() -> Option<EncryptedFile> {
    let path = match check_path("Encrypted file path") {
        Some(path) => {
            if !path.is_file() {
                println_error(&format!("It's not a file"));
                return None;
            }
            path
        }
        None => return None,
    };
    match EncryptedFile::new(path) {
        Ok(ef) => Some(ef),
        Err(err) => {
            println_error(&format!("Unhandled error while trying to open encrypted file - {err}"));
            None
        }
    }
}

const STRAIGHT_RIGHT: char = '├';
const STRAIGHT: char = '│';
const UP_RIGHT: char = '└';
const SPACE: char = ' ';
const DIRECTORY_PREFIX: &str = "<DIR>";
const FILE_PREFIX: &str = "<FILE>";

fn list_content_helper(content: &DirectoryContent, prefix: &str) {
    let last_file = content.get_files_iter().rev().take(1).next();
    let last_dir = if last_file.is_some() {
        None
    }
    else {
        content.get_dir_iter().rev().take(1).next()
    };
    for (name, dir) in content.get_dir_iter().rev().skip(last_dir.is_some() as usize).rev() {
        println!("{prefix}{STRAIGHT_RIGHT}{DIRECTORY_PREFIX} {name}");
        list_content_helper(dir, &format!("{prefix}{STRAIGHT}"));
    }
    if let Some((name, dir)) = last_dir {
        println!("{prefix}{UP_RIGHT}{DIRECTORY_PREFIX} {name}");
        list_content_helper(dir, &format!("{prefix}{SPACE}"));
    }
    for (name, file) in content.get_files_iter().rev().skip(1).rev() {
        println!("{prefix}{STRAIGHT_RIGHT}{FILE_PREFIX} {name} has_content: {}, has_key: {}, has_digest: {}, has_signature: {}", file.has_content(), file.has_key(), file.has_digest(), file.is_signed());
    }
    if let Some((name, file)) = last_file {
        println!("{prefix}{UP_RIGHT}{FILE_PREFIX} {name} has_content: {}, has_key: {}, has_digest: {}, has_signature: {}", file.has_content(), file.has_key(), file.has_digest(), file.is_signed());
    }
}

pub fn list_content(content: &DirectoryContent) {
    list_content_helper(content, "");
    println!();
}

pub fn get_zip_file_options() -> FileOptions {
    use the_lock_lib::CompressionMethod;
    loop {
        return match Confirm::new()
                .with_prompt("Use default zip file options")
                .interact()
                .expect("IO error") {
            true => FileOptions::default(),
            false => {
                match Select::new()
                        .with_prompt("Compression method")
                        .items(&[
                            "Deflated",
                            "Stored",
                            "Bzip2",
                            "Zstd",
                            "back",
                        ])
                        .default(0)
                        .interact()
                        .expect("IO error") {
                    0 => FileOptions::default()
                            .compression_method(CompressionMethod::Deflated)
                            .compression_level(Some(get_number_in_range("Compression rate [0;9]", 0..=9, 6))),
                    1 => FileOptions::default()
                            .compression_method(CompressionMethod::Stored),
                    2 => FileOptions::default()
                            .compression_method(CompressionMethod::Bzip2)
                            .compression_level(Some(get_number_in_range("Compression rate [0;9]", 0..=9, 6))),
                    3 => FileOptions::default()
                            .compression_method(CompressionMethod::Bzip2)
                            .compression_level(Some(get_number_in_range("Compression rate [-7;22]", -7..=22, 3))),               
                    _ => continue,
                }
            }
        };
    }
}

pub fn get_name_from_path(path: &str) -> &str {
    let mut p = path.len();
    for c in path.chars().rev() {
        if c == '/' || c == '\\' {
            break;
        }
        p -= 1;
    }
    path.get(p..).unwrap()
}

// TODO do it as macro
#[inline]
pub fn println_error(msg: &str) {
    println!("{}", console::Style::new().red().bold().apply_to(msg));
}
