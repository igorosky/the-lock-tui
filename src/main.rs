extern crate dialoguer;
mod utils;
mod key_handler;
mod signer_list_handler;
mod encrypted_file_handler;

use dialoguer::Select;
use encrypted_file_handler::handle_encrypted_file;
use key_handler::handle_key;
use signer_list_handler::handle_signers;

fn main() {
    let mut pos = 0;
    loop {
        pos = Select::new().items(&[
            "Encrypted File Manipulation",
            "Key Manipulation",
            "Signer List Manipulation",
            "Exit",
        ])
        .default(pos)
        .interact()
        .expect("IO error");
        match pos {
            0 => handle_encrypted_file(),
            1 => handle_key(),
            2 => handle_signers(),
            _ => return
        }
    }
}
