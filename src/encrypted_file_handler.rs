use std::fs::File;

use dialoguer::{Select, FuzzySelect, MultiSelect};
use indicatif::ProgressBar;
use the_lock_lib::{EncryptedFile, directory_content::{DirectoryContent, DirectoryContentPath}, DecryptFileResult, DecryptFileAndVerifyResult, DecryptFileAndFindSignerResult, error::EncryptedFileError};

use crate::utils::{open_file, get_path, get_public_key, get_private_rsa_key, create_encrypted_file, open_encrypted_file, check_path, get_private_key, create_file_with_default, get_public_rsa_key, open_signer_list, list_content, create_file, get_zip_file_options, println_error, green_font, error_font};

#[inline]
fn get_encryption_mode() -> usize {
    Select::new()
        .items(&[
            "Encrypt",
            "Encrypt and sign",
            "Exit",
        ])
        .default(0)
        .interact()
        .expect("IO error")
}

#[inline]
fn get_decryption_mode() -> usize {
    Select::new()
        .items(&[
            "Decrypt",
            "Decrypt and verify signature",
            "Decrypt and find signer",
            "Exit",
        ])
        .default(0)
        .interact()
        .expect("IO error")
}

pub fn handle_encrypted_file() {
    let mut pos = 0;
    loop {
        pos = Select::new()
                .items(&[
                    "Create new encrypted file",
                    "Open encrypted file",
                    "Exit",
                ])
                .default(pos)
                .interact()
                .expect("IO error");
        match pos {
            0 => encrypted_file_interactions(match create_encrypted_file() {
                Some(ef) => ef,
                None => continue,
            }),
            1 => encrypted_file_interactions(match open_encrypted_file() {
                Some(ef) => ef,
                None => continue,
            }),
            _ => return,
        }
    }
}

fn list_of_files_helper(content: &DirectoryContent, prefix: &str) -> Vec<String> {
    let mut ans = Vec::new();
    for (name, _) in content.get_files_iter() {
        ans.push(format!("{prefix}{}", name.as_str()));
    }
    for (name, directory) in  content.get_dir_iter() {
        ans.append(&mut list_of_files_helper(directory, &format!("{prefix}/{name}")));
    }
    ans
}

#[inline]
fn list_of_files(content: &DirectoryContent) -> Vec<String> {
    list_of_files_helper(content, "")
}

#[inline]
fn decrypted_file_output(result: DecryptFileResult) {
    match result {
        Ok(true) => println!("File has been decrypted and it's digiest is valid"),
        Ok(false) => println!("File has been decrypted but it's digest is invalid"),
        Err(EncryptedFileError::AsymetricKeyError(err)) => println_error(&format!("Decryption error, probably key is invalid - {}", err)),
        Err(err) => println_error(&format!("Unhandled error while decrypting file - {err}")),
    }
}

#[inline]
fn decrypted_file_and_find_signer_output(result: DecryptFileAndFindSignerResult) {
    match result {
        Ok((true, Some(name))) => println!("File has been decrypted, it's digiest is valid, signer is: {name}"),
        Ok((false, Some(name))) => println!("File has been decrypted, it's digiest is invalid, signer is: {name}"),
        Ok((true, None)) => println!("File has been decrypted, it's digiest is valid, signer hasn't been found"),
        Ok((false, None)) => println!("File has been decrypted, it's digiest is invalid, signer hasn't been found"),
        Err(EncryptedFileError::AsymetricKeyError(err)) => println_error(&format!("Decryption error, probably key is invalid - {}", err)),
        Err(err) => println_error(&format!("Uhandled error while decrypting file - {err}")),
    }
}

#[inline]
fn decrypted_file_and_verify_output(result: DecryptFileAndVerifyResult) {
    match result {
        Ok((true, Ok(()))) => println!("File has been decrypted, both digest and signature are valid"),
        Ok((false, Ok(()))) => println!("File has been decrypted, signature is valid, but digest not"),
        Ok((true, Err(err))) => println!("File has been decrypted, digest is valid, but signature not - {err}"),
        Ok((false, Err(err))) => println!("File has been decrypted, digest nor signature are valid - {err}"),
        Err(err) => println_error(&format!("Uhandled error while decrypting file - {err}")),
    }
}

fn encrypted_file_interactions(mut encrypted_file: EncryptedFile) {
    let mut pos = 0;
    loop {
        pos = Select::new()
                .items(&[
                    "Add file",
                    "Add directory",
                    "Decrypt file",
                    "Decrypt directory",
                    "List Content",
                    "Clone without",
                    "Set zip file options",
                    "Exit",
                ])
                .default(pos)
                .interact()
                .expect("IO error");
        match pos {
            0 => {
                println!("Add File");
                let src = match open_file("Path to file which is suppoused to be encrypted") {
                    Some(file) => file,
                    None => continue,
                };
                match src.metadata() {
                    Ok(metadata) => encrypted_file.set_zip_file_options(encrypted_file.zip_file_options().large_file(metadata.len() >= 4*1024*1024*1024)),
                    Err(err) => {
                        println_error(&format!("Couldn't read file size - {err}"));
                        continue;
                    }
                }
                let dst_path = DirectoryContentPath::from(get_path("Destination path"));
                let public_key = match get_public_key() {
                    Some(key) => key,
                    None => continue,
                };
                let result = match get_encryption_mode() {
                    0 => encrypted_file.add_file(src, &dst_path, &public_key),
                    1 => {
                        encrypted_file.add_file_and_sign(src, &dst_path, &public_key, &match get_private_rsa_key() {
                            Some(key) => key,
                            None => continue,
                        })
                    },
                    _ => continue,
                };
                match result {
                    Ok(()) => println!("File successfully added"),
                    Err(err) => println_error(&format!("Error occured when trying to add a file - {err}")),
                }
            }
            1 => {
                println!("Add Directory");
                    let src = match check_path("Path to directory which is suppoused to be encrypted") {
                        Some(dir) => {
                            if !dir.is_dir() {
                                println_error(&format!("It's not an directory"));
                                continue;
                            }
                            dir
                        },
                        None => continue,
                    };
                    let dst_path = DirectoryContentPath::from(get_path("Destination path"));
                    let public_key = match get_public_key() {
                        Some(key) => key,
                        None => continue,
                    };
                    let bar = ProgressBar::new(0);
                    let result =  match get_encryption_mode() {
                        0 => encrypted_file.add_directory_callback(src, dst_path, &public_key, |len| bar.set_length(len as u64),
                        |src, dst, res| {
                            match res {
                                Ok(()) => bar.println(format!("{:?} saved to dst {}", src, dst)),
                                Err(err) => bar.println(format!("Couldn't save {:?} to {} - {}", src, dst, err)),
                            }
                            bar.inc(1);
                        }, |success| match success {
                            true => bar.finish_and_clear(),
                            false => bar.finish_and_clear(),
                        }),
                        1 => encrypted_file.add_directory_and_sign_callback(src, dst_path, &public_key, &match get_private_rsa_key() {
                            Some(mut key) => if let Err(err) = key.precompute() {
                                println_error(&format!("RSA precomputions failed - {}", err));
                                continue;
                            }
                            else {
                                key
                            },
                            None => continue,
                        }, |len| bar.set_length(len as u64), |src, dst, res| {
                            match res {
                                Ok(()) => bar.println(format!("{:?} saved to dst {}", src, dst)),
                                Err(err) => bar.println(format!("Couldn't save {:?} to {} - {}", src, dst, err)),
                            }
                            bar.inc(1);
                        }, |success| match success {
                            true => bar.finish_and_clear(),
                            false => bar.finish_and_clear(),
                        }),
                        _ => continue,
                    };
                    match result {
                        Ok(_) => println!("Directory encrypted"),
                        Err(err) => println_error(&format!("Error occured when trying to add a directory - {err}")),
                    }
            }
            2 => {
                let src = DirectoryContentPath::from({
                    let content = list_of_files(match encrypted_file.get_directory_content() {
                        Ok(content) => content,
                        Err(err) => {
                            println_error(&format!("Couldn't read file content - {err}"));
                            continue;
                        }
                    });
                    content[FuzzySelect::new()
                    .with_prompt("File to decrypt")
                    .items(&content)
                    .interact()
                    .expect("IO error")].clone()
                });
                let private_key = match get_private_key() {
                    Some(key) => key,
                    None => continue,
                };
                let dst = match create_file_with_default(src.file_name().expect("File has name?").to_owned()) { // TODO 
                    Some(file) => file,
                    None => continue,
                };
                match get_decryption_mode() {
                    0 => decrypted_file_output(encrypted_file.decrypt_file(&src, dst, &private_key)),
                    1 => decrypted_file_and_verify_output(encrypted_file.decrypt_file_and_verify(&src, dst, &private_key, &match get_public_rsa_key() {
                            Some(key) => key,
                            None => continue,
                        })),
                    2 => decrypted_file_and_find_signer_output(encrypted_file.decrypt_file_and_find_signer(&src, dst, &private_key, &match open_signer_list() {
                            Some(sl) => sl,
                            None => continue,
                        })),
                    _ => continue,
                };
            }
            3 => {
                let src = DirectoryContentPath::from(get_path("Source path"));
                let dst = match check_path("Output path") {
                    Some(path) => path,
                    None => continue,
                };
                let private_key = match get_private_key() {
                    Some(mut key) => if let Err(err) = key.rsa_precomput() {
                        println_error(&format!("RSA precomputions failed - {}", err));
                        continue;
                    }
                    else {
                        key
                    },
                    None => continue,
                };
                if let Err(err) = encrypted_file.get_directory_content() {
                    println_error(&format!("Couldn't retrive directory content - {}", err));
                    continue;
                }
                let bar = ProgressBar::new(0);
                match get_decryption_mode() {
                    0 => {
                        match encrypted_file.decrypt_directory_callback(src, dst, &private_key, |len| bar.set_length(len as u64),
                        |src, dst, res| {
                            bar.inc(1);
                            match res {
                                Ok(true) => bar.suspend(|| println!("{} saved to destination {:?} - digest is correct", src, dst)),
                                Ok(false) => bar.suspend(|| println_error(&format!("{} saved to destination {:?} - digest is INCORRECT", src, dst))),
                                Err(err) => bar.suspend(|| println_error(&format!("Couldn't save {} to {:?} - {}", src, dst, err))),
                            }
                        }, |_| bar.finish_and_clear()) {
                            Ok(_) => println!("Directory decrypted"),
                            Err(err) => println_error(&format!("Unhandled error while decrypting directory - {err}")),
                        };
                    }
                    1 => {
                        match encrypted_file.decrypt_directory_and_verify_callback(src, dst, &private_key, &match get_public_rsa_key() {
                            Some(key) => key,
                            None => continue,
                        },
                        |len| bar.set_length(len as u64),
                        |src, dst, res| {
                            bar.inc(1);
                            match res {
                                Ok((digest, signature)) => bar.println(format!("{} saved to dst {:?} - digest is {}, signature is {}", src, dst,
                                    match digest {
                                        true => green_font("CORRECT"),
                                        false => error_font("INCORRECT"),
                                    },
                                    match signature.is_ok() {
                                        true => green_font("VALID"),
                                        false => error_font("INVALID"),
                                    })),
                                Err(EncryptedFileError::FileIsNotSigned) => {
                                    bar.println(format!("File {} is not signed, decrypting it without verification", src));
                                    let result = encrypted_file.decrypt_file(src, match File::create(dst) {
                                        Ok(file) => file,
                                        Err(err) => {
                                            bar.suspend(|| println_error(&format!("Couldn't create file {} - {}", dst, err)));
                                            return;
                                        }
                                    }, &private_key);
                                    bar.suspend(|| decrypted_file_output(result));
                                }
                                Err(err) => bar.println(format!("Couldn't save {} to {:?} - {}", src, dst, err)),
                            }
                        },
                        |_| bar.finish_and_clear()) {
                            Ok(_) => println!("Directory decrypted"),
                            Err(err) => println_error(&format!("Unhandled error while decrypting directory - {err}")),
                        }
                    }
                    2 => {
                        match encrypted_file.decrypt_directory_and_find_signer_callback(src, dst, &private_key, &match open_signer_list() {
                            Some(sl) => sl,
                            None => continue,
                        },
                        |len| bar.set_length(len as u64),
                        |src, dst, res| {
                            bar.inc(1);
                            match res {
                                Ok((digest, signer)) => bar.println(format!("{} saved to dst {:?} - digest is {}, signer: {}", src, dst, 
                                    match digest {
                                        true => green_font("VALID"),
                                        false => error_font("INVALID"),
                                    }, signer.to_owned().unwrap_or("<UNKNOWN>".to_owned()))),
                                Err(EncryptedFileError::FileIsNotSigned) => {
                                    bar.println(format!("File {} is not signed, decrypting it without verification", src));
                                    let result = encrypted_file.decrypt_file(src, match File::create(dst) {
                                        Ok(file) => file,
                                        Err(err) => {
                                            bar.println(format!("Couldn't create file {} - {}", dst, err));
                                            return;
                                        }
                                    }, &private_key);
                                    bar.suspend(|| decrypted_file_output(result));
                                }
                                Err(err) => bar.println(format!("Couldn't save {} to {:?} - {}", src, dst, err)),
                            }
                        },
                        |_| bar.finish_and_clear()) {
                            Ok(_) => println!("Directory decrypted"),
                            Err(err) => println_error(&format!("Uhandled error while decrypting directory - {err}")),
                        }
                    }
                    _ => continue,
                };
            }
            4 => list_content(match encrypted_file.get_directory_content() {
                Ok(dc) => dc,
                Err(err) => {
                    println_error(&format!("Unhandled error while getting file content - {err}"));
                    continue;
                }
            }),
            5 => {
                let output_file = match create_file() {
                    Some(file) => file,
                    None => continue,
                };
                let files_to_delete: Vec<DirectoryContentPath> = {
                    let files = list_of_files(match encrypted_file.get_directory_content() {
                        Ok(dc) => dc,
                        Err(err) => {
                            println_error(&format!("Unhandled error while getting file content - {err}"));
                            continue;
                        }
                    });
                    MultiSelect::new()
                        .items(&files)
                        .interact()
                        .expect("IO error")
                        .into_iter()
                        .map(|pos| DirectoryContentPath::from(files[pos].as_str()))
                        .collect()
                };
                match encrypted_file.delete_path(output_file, &files_to_delete) {
                    Ok(()) => println!("File has been copied with indicated files omited"),
                    Err(err) => println_error(&format!("Unhandled error while copying files - {err}")),
                }
            }
            6 => {
                println!("!!! Zip file options lasts til you leave this menu !!!");
                encrypted_file.set_zip_file_options(get_zip_file_options());
            }
            _ => return,
        }
    }
}
