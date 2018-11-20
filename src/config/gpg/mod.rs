use errors::*;
use std::ffi::OsString;
use std::fs;
use std::fs::{DirBuilder, File};
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;

fn create_gpg_folder(gpg_path: String) -> Result<()> {
    Command::new("mkdir")
        .arg(format!("{}", gpg_path))
        .output()
        .or_else(|i| {
            Err(ErrorKind::RuntimeError(
                format!("Could not create config folder: {}", i).to_owned(),
            ))
        })?;
    Ok(())
}

fn create_gpg_batch_file() -> Result<()> {
    let command = include_str!("../../shell/gpg_config");
    let mut file = File::create("foo").or(Err(ErrorKind::RuntimeError(
        "Could not create GPG config file.".to_owned(),
    )))?;
    file.write_all(command.to_owned().as_bytes())
        .or(Err(ErrorKind::RuntimeError(
            "Could not write to GPG config file.".to_owned(),
        )))?;
    Ok(())
}

fn create_gpg_keys(gpg_path: String) -> Result<()> {
    let command = Command::new("gpg")
        .arg(format!("--homedir={}", gpg_path))
        .arg("--batch")
        .arg("--generate-key")
        .arg("foo")
        .output()?;

    if !command.status.success() {
        return Err(ErrorKind::RuntimeError(
            format!(
                "Generating key files failed: {}",
                String::from_utf8(command.stderr)?
            )
            .to_owned(),
        )
        .into());
    }

    Ok(())
}

fn export_pubkey(gpg_path: String) -> Result<String> {
    let output = Command::new("gpg")
        .arg(format!("--homedir={}", gpg_path))
        .arg("--armor")
        .arg("--export")
        .arg("culper@culper")
        .output()?;

    if !output.status.success() {
        return Err(ErrorKind::RuntimeError(
            format!(
                "Generating key files failed: {}",
                String::from_utf8(output.stderr)?
            )
            .to_owned(),
        )
        .into());
    }

    Ok(String::from_utf8(output.stdout)?)
}

pub fn create_gpg_config(gpg_path: String) -> Result<()> {
    create_gpg_folder(gpg_path)?;
    Ok(())
}

pub fn create_gpg_server_config(gpg_path: String) -> Result<()> {
    create_gpg_folder(gpg_path.to_owned())?;
    create_gpg_batch_file()?;
    create_gpg_keys(gpg_path.to_owned())?;
    DirBuilder::new().create("public")?;

    export_pubkey(gpg_path.to_owned())
        .and_then(|key| {
            File::create("public/pubkey.asc")
                .or(Err(ErrorKind::RuntimeError(
                    "Could not create public key-file.".to_owned(),
                )))?
                .write_all(key.to_owned().as_bytes())
                .or(Err(ErrorKind::RuntimeError(
                    "Could not write to public key-file.".to_owned(),
                )))?;
            Ok(())
        })
        .and_then(|_| {
            fs::remove_file("foo").or_else(|err| {
                println!(
                    "Could not delete temporary batch config: {}",
                    err.to_string()
                );
                Ok(())
            })
        })?;

    Ok(())
}

pub fn has_config(gpg_path: String) -> bool {
    Path::new("public/pubkey.asc").exists()
        && Path::new(&OsString::from(format!("{}/pubring.kbx", gpg_path))).exists()
}
