use dialoguer::Select;
use the_lock_lib::{asymetric_key::{PrivateKey, PublicKey, MIN_RSA_KEY_SIZE}, rsa::{RsaPrivateKey, RsaPublicKey}};

use crate::utils::{save, read, get_number_in_range, println_error};

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
                    get_number_in_range("Key size", MIN_RSA_KEY_SIZE..usize::MAX, MIN_RSA_KEY_SIZE)
                    ) {
                        Ok(ans) => ans,
                        Err(err) => {
                            println_error(&format!("Unexpected error - {err}"));
                            continue;
                        }
                    });
            },
            1 => {
                if let Some(key) = read::<PrivateKey>("Private key path") {
                    private_key_interactions(key);
                }
            },
            2 => {
                if let Some(key) = read::<PublicKey>("Public key path") {
                    public_key_interactions(key);
                }
            },
            3 => {
                if let Some(key) = read::<RsaPrivateKey>("Private RSA key path") {
                    private_rsa_key_interactions(key);
                }
            },
            4 => {
                if let Some(key) = read::<RsaPublicKey>("Public RSA key path") {
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
                    false => println_error(&format!("Failed to save a key")),
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
