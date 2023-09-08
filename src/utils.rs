use std::{path::Path, fs::{File, create_dir}, io::{Read, Write}};

use dialoguer::{Confirm, Password, Input};
use serialize_with_password::{Serialize, Deserialize, serialize_serde_no_pass, serialize_serde, is_encrypted, deserialize_serde, deserialize_serde_no_pass};
use the_lock_lib::signers_list::SignersList;

fn delete_path<P: AsRef<Path>>(path: P) {
    match (path.as_ref().is_file(), path.as_ref().is_dir()) {
        (true, _) => std::fs::remove_file(path).expect("Could't delete file"),
        (_, true) => std::fs::remove_dir_all(path).expect("Could't delete directory"),
        _ => (),
    }
}

#[inline]
fn get_path() -> String {
    Input::<String>::new().with_prompt("File path").interact().expect("IO error")
}

#[inline]
fn prepate_path() -> Option<Box<Path>> {
    let target = get_path();
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
                            println!("Couldn't save data to file - {}", err);
                            false
                        }
                    }
                }
                Err(err) => {
                    println!("Couldn't create a file - {}", err);
                    false
                }
            }
        }
        Err(err) => {
            println!("Unexpected error while saving file - {}", err);
            false
        }
    }
}

#[inline]
fn check_path() -> Option<Box<Path>> {
    let src = get_path();
    let path = Path::new(&src);
    if !path.exists() {
        println!("Path {src} does't exists");
        return None;
    }
    Some(Box::from(path))
}

pub fn read<T: for<'a> Deserialize<'a>>() -> Option<T> {
    let path = match check_path() {
        Some(path) => path,
        None => return None,
    };
    if !path.is_file() {
        println!("It's is not a file");
        return None;
    }
    let mut buf = Vec::new();
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            println!("Unhandled error while opening file - {err}");
            return None;
        }
    };
    if let Err(err) = file.read_to_end(&mut buf) {
        println!("Unhandled error while reading file - {err}");
        return None;
    }
    let is_enc = match is_encrypted(&buf) {
        Ok(ans) => ans,
        Err(serialize_with_password::Error::DataIsEmpty) => {
            println!("File is empty");
            return None;
        }
        Err(err) => {
            println!("Unexpected error while checking if file is encrypted - {err}");
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
                println!("Unhandled error while deserializing file - {err}");
            }
            ans.ok()
        }
        false => match deserialize_serde_no_pass(&buf) {
            Ok(ans) => Some(ans),
            Err(err) => {
                println!("Unhandled error while deserializing file - {err}");
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
        println!("Couldn't create a directory for signers list - {}", err);
        return None;
    }
    SignersList::new(Path::new(&Input::<String>::new().with_prompt("File path").interact().expect("IO error"))).ok()
}

pub fn open_signer_list() -> Option<SignersList> {
    let path = match check_path() {
        Some(path) => path,
        None => return None,
    };
    if !path.is_dir() {
        println!("It's is not a directory");
        return None;
    }
    match SignersList::open(path) {
        Ok(ans) => Some(ans),
        Err(err) => {
            println!("Unexpected error while opening a signers list - {err}");
            None
        }
    }
}
