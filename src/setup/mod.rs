use config::create;
use config::gpg::{create_gpg_config, create_gpg_server_config};
use errors::*;
use gpg::GpgManager;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};

pub fn setup(gpg_path: &str, config_path: &str) -> Result<()> {
    println!("Creating config");
    create_gpg_config(gpg_path)?;
    let mut me_key = String::new();
    let _ = stdout().flush();
    let gpg_manager = GpgManager::new(&gpg_path.to_string())?;
    stdin()
        .read_to_string(&mut me_key)
        .map(|_| gpg_manager.import_key(&me_key))??;

    let user_config = gpg_manager.parse_private_key()?;
    create(user_config.email, user_config.id, config_path.to_string())?;

    Ok(())
}

pub fn server_setup(gpg_config: &str, config_path: &str) -> Result<()> {
    println!("Creating server config");
    create_gpg_server_config(gpg_config)?;
    let gpg_manager = GpgManager::new(&gpg_config.to_owned())?;
    let server_config = gpg_manager.parse_private_key()?;
    create(
        server_config.email,
        server_config.id,
        config_path.to_string(),
    )?;
    Ok(())
}
