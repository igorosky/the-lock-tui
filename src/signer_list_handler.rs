use dialoguer::{Select, Input, FuzzySelect};
use the_lock_lib::signers_list::SignersList;
use crate::key_handler::public_rsa_key_interactions;

use crate::utils::{create_signers_list, open_signer_list, get_public_rsa_key};

pub fn handle_signers() {
    let mut pos = 0;
    loop {
        pos = Select::new()
        .items(&[
            "Create new",
            "Open",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => {
                if let Some(sl) = create_signers_list() {
                    signers_list_manipulation(sl);
                }
            },
            1 => {
                if let Some(sl) = open_signer_list() {
                    signers_list_manipulation(sl);
                }
            }
            _ => return,
        }
    }
}

fn choose_signer(signers_list: &SignersList) -> String {
    let mut signers = Vec::new();
    for (name, _) in signers_list.into_iter() {
        signers.push(name);
    }
    signers[
        FuzzySelect::new()
            .items(&signers)
            .with_prompt("Choose signers to delete")
            .interact()
            .expect("IO error")
    ].to_owned()
}

fn signers_list_manipulation(mut signers_list: SignersList) {
    let mut pos = 0;
    println!("Signer's list contains {} signers", signers_list.len());
    loop {
        pos = Select::new()
                .items(&[
                    "Add signer",
                    "List signers",
                    "Delete",
                    "Extract signer public key",
                    "Exit",
                ])
                .default(pos)
                .interact()
                .expect("IO error");
        match pos {
            0 => {
                let name = &Input::<String>::new()
                .with_prompt("Signer name")
                .validate_with(|v: &String| -> Result<(), &str> {
                    match signers_list.contains(&v) {
                        true => Err("Signer with such name already exists"),
                        false => Ok(())
                    }
                })
                .interact()
                .expect("IO error");
                match signers_list.add_signer(
                    &name,
                    &match get_public_rsa_key() {
                        Some(key) => key,
                        None => continue,
                    },
                ) {
                    Ok(()) => println!("Signer successfully added"),
                    Err(err) => println!("Unexpected error while adding signer to the list - {err}"),
                }
            },
            1 => {
                println!("List of signers:");
                for (name, _) in signers_list.into_iter() {
                    println!("{name}");
                }
            },
            2 => {
                println!("Delete signer");
                match signers_list.delete_signer(&choose_signer(&signers_list)) {
                    Ok(()) => println!("Signer has been deleted"),
                    Err(err) => println!("Unhandled error while trying to delete sigener - {err}"),
                }
            },
            3 => {
                println!("Extract signer's RSA public key");
                match signers_list.get_signers_key(&choose_signer(&signers_list)) {
                    Ok(key) => {
                        println!("Got RSA public key");
                        public_rsa_key_interactions(key);
                    },
                    Err(err) => println!("Unhandled error while trying to possess signer's key - {err}"),
                }
            },
            _ => return,
        }
    }
}
