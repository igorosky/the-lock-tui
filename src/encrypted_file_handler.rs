use dialoguer::{Select, FuzzySelect, MultiSelect};
use the_lock_lib::{EncryptedFile, directory_content::DirectoryContent, DecryptFileResult, DecryptFileAndVerifyResult, DecryptFileAndFindSignerResult};

use crate::utils::{open_file, get_path, get_public_key, get_private_rsa_key, create_encrypted_file, open_encrypted_file, check_path, get_private_key, create_file_with_default, get_public_rsa_key, open_signer_list, list_content, create_file};

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
        Err(err) => println!("Unhandled error while decrypting file - {err}"),
    };
}

#[inline]
fn decrypted_file_and_find_signer_output(result: DecryptFileAndFindSignerResult) {
    match result {
        Ok((true, Some(name))) => println!("File has been decrypted, it's digiest is valid, signer is: {name}"),
        Ok((false, Some(name))) => println!("File has been decrypted, it's digiest is invalid, signer is: {name}"),
        Ok((true, None)) => println!("File has been decrypted, it's digiest is valid, signer hasn't been found"),
        Ok((false, None)) => println!("File has been decrypted, it's digiest is invalid, signer hasn't been found"),
        Err(err) => println!("Uhandled error while decrypting file - {err}"),
    }
}

#[inline]
fn decrypted_file_and_verify_output(result: DecryptFileAndVerifyResult) {
    match result {
        Ok((true, Ok(()))) => println!("File has been decrypted, both digest and signature are valid"),
        Ok((false, Ok(()))) => println!("File has been decrypted, signature is valid, but digest not"),
        Ok((true, Err(err))) => println!("File has been decrypted, digest is valid, but signature not - {err}"),
        Ok((false, Err(err))) => println!("File has been decrypted, digest nor signature are valid - {err}"),
        Err(err) => println!("Uhandled error while decrypting file - {err}"),
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
                    "Exit",
                ])
                .default(pos)
                .interact()
                .expect("IO error");
        match pos {
            0 => {
                println!("Add File");
                let sign = match get_encryption_mode() {
                    0 => false,
                    1 => true,
                    _ => continue,
                };
                let src = match open_file() {
                    Some(file) => file,
                    None => continue,
                };
                let dst_path = get_path();
                let public_key = match get_public_key() {
                    Some(key) => key,
                    None => continue,
                };
                let result = if sign {
                    encrypted_file.add_file_and_sign(src, &dst_path, &public_key, &match get_private_rsa_key() {
                        Some(key) => key,
                        None => continue,
                    })
                }
                else {
                    encrypted_file.add_file(src, &dst_path, &public_key)
                };
                match result {
                    Ok(()) => println!("File successfully added"),
                    Err(err) => println!("Error occured when trying to add a file - {err}"),
                }
            }
            1 => {
                println!("Add Directory");
                    let src = match check_path() {
                        Some(dir) => {
                            if !dir.is_dir() {
                                println!("It's not an directory");
                                continue;
                            }
                            dir
                        },
                        None => continue,
                    };
                    let dst_path = get_path();
                    let public_key = match get_public_key() {
                        Some(key) => key,
                        None => continue,
                    };
                    let result =  match get_encryption_mode() {
                        0 => encrypted_file.add_directory(src, &dst_path, &public_key),
                        1 => encrypted_file.add_directory_and_sign(src, &dst_path, &public_key, &match get_private_rsa_key() {
                            Some(key) => key,
                            None => continue,
                        }),
                        _ => continue,
                    };
                    match result {
                        Ok(results) => {
                            for (path, result) in results {
                                let path = path.to_str().unwrap_or("<unknown>");
                                match result {
                                    Ok(()) => println!("File {path} successfully added"),
                                    Err(err) => println!("Adding file {path} failed - {err}"),
                                }
                            }
                        },
                        Err(err) => println!("Error occured when trying to add a directory - {err}"),
                    }
            }
            2 => {
                let private_key = match get_private_key() {
                    Some(key) => key,
                    None => continue,
                };
                let src = {
                    let content = list_of_files(match encrypted_file.get_directory_content() {
                        Ok(content) => content,
                        Err(err) => {
                            println!("Couldn't read file content - {err}");
                            continue;
                        }
                    });
                    content[FuzzySelect::new()
                        .items(&content)
                        .interact()
                        .expect("IO error")].clone()
                };
                let dst = match create_file_with_default("value".to_owned()) {
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
                let private_key = match get_private_key() {
                    Some(key) => key,
                    None => continue,
                };
                let src = {
                    let content = list_of_files(match encrypted_file.get_directory_content() {
                        Ok(content) => content,
                        Err(err) => {
                            println!("Couldn't read file content - {err}");
                            continue;
                        }
                    });
                    content[FuzzySelect::new()
                        .items(&content)
                        .interact()
                        .expect("IO error")].clone()
                };
                let dst = match check_path() {
                    Some(path) => path,
                    None => continue,
                };
                match get_decryption_mode() {
                    0 => {
                        match encrypted_file.decrypt_directory(&src, dst, &private_key) {
                            Ok(results) => {
                                println!("Directory has been decrypted with result:");
                                for (name, result) in results {
                                    print!("{name}");
                                    decrypted_file_output(result);
                                }
                            }
                            Err(err) => println!("Unhandled error while decrypting directory - {err}"),
                        };
                    }
                    1 => {
                        match encrypted_file.decrypt_directory_and_verify(&src, dst, &private_key, &match get_public_rsa_key() {
                            Some(key) => key,
                            None => continue,
                        }) {
                            Ok(results) => {
                                println!("Directory has been decrypted with result:");
                                results.into_iter().for_each(|(name, result)| {
                                    print!("{name}: ");
                                    decrypted_file_and_verify_output(result);
                                });
                            }
                            Err(err) => println!("Unhandled error while decrypting directory - {err}")
                        }
                    }
                    2 => {
                        match encrypted_file.decrypt_directory_and_find_signer(&src, dst, &private_key, &match open_signer_list() {
                            Some(sl) => sl,
                            None => continue,
                        }) {
                            Ok(results) => {
                                println!("Directory has been decrypted with result:");
                                for (name, result) in results {
                                    print!("{name}");
                                    decrypted_file_and_find_signer_output(result);
                                }
                            }
                            Err(err) => println!("Uhandled error while decrypting directory - {err}"),
                        }
                    }
                    _ => continue,
                };
            }
            4 => list_content(match encrypted_file.get_directory_content() {
                Ok(dc) => dc,
                Err(err) => {
                    println!("Unhandled error while getting file content - {err}");
                    continue;
                }
            }),
            5 => {
                let output_file = match create_file() {
                    Some(file) => file,
                    None => continue,
                };
                let files_to_delete: Vec<String> = {
                    let files = list_of_files(match encrypted_file.get_directory_content() {
                        Ok(dc) => dc,
                        Err(err) => {
                            println!("Unhandled error while getting file content - {err}");
                            continue;
                        }
                    });
                    MultiSelect::new()
                        .items(&files)
                        .interact()
                        .expect("IO error")
                        .into_iter()
                        .map(|pos| files[pos].clone())
                        .collect()
                };
                match encrypted_file.delete_path(output_file, &files_to_delete) {
                    Ok(()) => println!("File has been copied with indicated files omited"),
                    Err(err) => println!("Unhandled error while copying files - {err}"),
                }
            }
            _ => return,
        }
    }
}
