use dialoguer::Select;

pub fn handle_encrypted_file() {
    let mut pos = 0;
    loop {
        pos = Select::new()
                .items(&[
                    ""
                ])
                .default(pos)
                .interact()
                .expect("IO error");
        match pos {
            _ => return,
        }
    }
}
