use dialoguer::{Select, Input};
use the_lock_lib::{asymetric_key::{PrivateKey, self, PublicKey}, rsa::{RsaPrivateKey, RsaPublicKey}};

use crate::utils::{save, read};

pub fn handle_key() {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Create new private key",
            "Open existing private key",
            "Open existing public key",
            "Open existing private RSA key",
            "Open existing public RSA key",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                println!("Creating new private key");
                private_key_interactions(match PrivateKey::new(
                    Input::new()
                            .with_prompt("Key size")
                            .validate_with(|input: &String| -> Result<(), &str> {
                                match input.parse::<usize>() {
                                    Ok(val) => match val.cmp(&asymetric_key::MIN_RSA_KEY_SIZE) {
                                        std::cmp::Ordering::Less => Err("Value is too small"),
                                        _ => Ok(()),
                                    }
                                    Err(_) => Err("It's not a number"),
                                }
                            })
                            .interact()
                            .expect("IO error").parse::<usize>().expect("Number was expected")
                    ) {
                        Ok(ans) => ans,
                        Err(err) => {
                            println!("Unexpected error - {err}");
                            continue;
                        }
                    });
            },
            1 => {
                println!("Opening private key");
                if let Some(key) = read::<PrivateKey>() {
                    private_key_interactions(key);
                }
            },
            2 => {
                println!("Opening public key");
                if let Some(key) = read::<PublicKey>() {
                    public_key_interactions(key);
                }
            },
            3 => {
                println!("Opening private RSA key");
                if let Some(key) = read::<RsaPrivateKey>() {
                    private_rsa_key_interactions(key);
                }
            },
            4 => {
                println!("Opening public RSA key");
                if let Some(key) = read::<RsaPublicKey>() {
                    public_rsa_key_interactions(key);
                }
            },
            _ => return,
        }
    }
}

fn private_key_interactions(key: PrivateKey) {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Save to",
            "Get public key",
            "Get private RSA key",
            "Get public RSA key",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                println!("Saving Key");
                match save(&key) {
                    true => println!("Key saved"),
                    false => println!("Failed to save a key"),
                }
            },
            1 => public_key_interactions(key.get_public_key()),
            2 => private_rsa_key_interactions(key.get_rsa_private_key().to_owned()),
            3 => public_rsa_key_interactions(key.get_rsa_public_key()),
            _ => return,
        }
    }
}

fn public_key_interactions(key: PublicKey) {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Save to",
            "Get public RSA key",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                save(&key);
            },
            1 => public_rsa_key_interactions(key.get_rsa_public_key().to_owned()),
            _ => return,
        }
    }
}

fn private_rsa_key_interactions(key: RsaPrivateKey) {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Save to",
            "Get public RSA key",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                save(&key);
            },
            1 => public_rsa_key_interactions(key.to_public_key()),
            _ => return,
        }
    }
}

pub fn public_rsa_key_interactions(key: RsaPublicKey) {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Save to",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                save(&key);
            },
            _ => return,
        }
    }
}
