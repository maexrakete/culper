use config::create;
use config::gpg::{create_gpg_config, create_gpg_server_config};
use errors::*;
use gpg::*;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};

pub fn setup() -> Result<()> {
    create_gpg_config()?;
    let mut me_key = String::new();
    let _ = stdout().flush();
    stdin()
        .read_to_string(&mut me_key)
        .map(|_| import_key(me_key))??;

    let user_config = parse_private_key()?;
    create(user_config.email, user_config.id, None);

    Ok(())
}

pub fn server_setup() -> Result<()> {
    create_gpg_server_config()?;
    let server_config = parse_private_key()?;
    create(server_config.email, server_config.id, None);
    Ok(())
}
