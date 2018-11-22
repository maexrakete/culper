use clap::ArgMatches;
use config::UserConfig;
use duct::cmd;
use errors::*;
use regex::Regex;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};
use std::process::{Command, Stdio};
use vault::{SealedVault, UnsealedVault, VaultHandler};

pub struct PubKeyVaultHandler {
    recipient: String,
    gpg_path: String,
}

impl PubKeyVaultHandler {
    pub fn new(recipient: String, gpg_path: String) -> PubKeyVaultHandler {
        PubKeyVaultHandler {
            recipient: recipient,
            gpg_path: gpg_path,
        }
    }
}

impl VaultHandler for PubKeyVaultHandler {
    fn encrypt(&self, open_vault: UnsealedVault) -> Result<SealedVault> {
        let gpg_manager = GpgManager::new(self.gpg_path.to_owned())?;
        Ok(SealedVault {
            secret: gpg_manager.encrypt(open_vault.plain_secret, self.recipient.to_owned())?,
            format: open_vault.format,
        })
    }

    fn decrypt(&self, open_vault: SealedVault) -> Result<UnsealedVault> {
        let gpg_manager = GpgManager::new(self.gpg_path.to_owned())?;
        Ok(UnsealedVault {
            plain_secret: String::from_utf8(gpg_manager.decrypt(open_vault.secret)?).unwrap(),
            format: open_vault.format,
        })
    }
}

pub struct GpgManager {
    pub gpg_path: String,
}

impl GpgManager {
    pub fn new(gpg_path: String) -> Result<GpgManager> {
        Ok(GpgManager { gpg_path: gpg_path })
    }

    // Takes the armored exported public key and returns either an error or a
    // result containing the ID of the imported key
    pub fn import_key(&self, gpg_key: String) -> Result<String> {
        let mut child = Command::new("gpg")
            .arg(format!("--homedir={}", &self.gpg_path))
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(gpg_key.as_bytes())?;
        }
        let output = child.wait_with_output().expect("Failed to read stdout");
        if !output.status.success() {
            return Err(ErrorKind::RuntimeError(format!(
                "Key was not imported. Error: [{}]: {}",
                output.status,
                String::from_utf8(output.stderr)?
            ))
            .into());
        };
        let expr = Regex::new("[0-9A-Z]{16}").unwrap();
        let raw_output = String::from_utf8(output.stderr)?;
        match expr.captures(&raw_output) {
            Some(matches) => {
                if &matches.len() == &1usize {
                    Ok(matches.get(0).unwrap().as_str().to_string())
                } else {
                    Err(ErrorKind::RuntimeError(format!(
                        "Could not extract the key id from gpg output: {}",
                        raw_output
                    ))
                    .into())
                }
            }
            _ => Err(ErrorKind::RuntimeError(format!(
                "Could not extract the key id from gpg output: {}",
                raw_output
            ))
            .into()),
        }
    }

    pub fn parse_private_key(&self) -> Result<UserConfig> {
        let process = Command::new("gpg")
            .arg(format!("--homedir={}", &self.gpg_path))
            .arg("--with-colons")
            .arg("--list-secret-keys")
            .arg("--keyid-format")
            .arg("long")
            .output()?;

        if !process.status.success() {
            return Err(ErrorKind::RuntimeError(format!(
                "Could not list keys. Error: [{}]: {}",
                process.status,
                String::from_utf8(process.stderr)?
            ))
            .into());
        }

        let list = String::from_utf8(process.stdout)?;
        let config_lines: Vec<&str> = list
            .lines()
            .into_iter()
            .filter(|line| line.starts_with("sec") || line.starts_with("uid"))
            .collect();
        let config_items: Vec<Vec<&str>> = config_lines
            .into_iter()
            .map(|line| line.split(":").collect())
            .collect();

        // TODO: More exhaustive error reporting.
        match (config_items.get(0), config_items.get(1)) {
            (Some(sec_config), Some(uid_config)) => match (
                sec_config.get(4),
                extract_mail_from_uid(uid_config.get(9).cloned()),
            ) {
                (Some(keyid), Some(mail)) => Ok(UserConfig {
                    id: keyid.to_string(),
                    email: mail,
                }),
                _ => Err(ErrorKind::RuntimeError(
                    "Could not reliably determine Key-ID or E-Mail from GPG output.".to_owned(),
                )
                .into()),
            },
            _ => Err(ErrorKind::RuntimeError(format!(
                "Could not reliably determine sec and uid lines from gpg output. \
                 Output was: \
                 {}",
                list
            ))
            .into()),
        }
    }

    pub fn verify(&self, content: String, signature: String) -> Result<bool> {
        let content_file = cmd!("mktemp").read()?;
        let signature_file = cmd!("mktemp").read()?;
        cmd!("echo", &content).stdout(&content_file).run()?;
        cmd!("echo", &signature)
            .pipe(cmd!("base64", "-d").stdout(&signature_file))
            .run()?;

        match cmd!(
            "gpg",
            format!("--homedir={}", &self.gpg_path),
            "--verify",
            &signature_file,
            &content_file
        )
        .stdout_capture()
        .stderr_capture()
        .run()
        {
            Ok(outcome) => {
                if outcome.status.success() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(ErrorKind::RuntimeError(
                "Could not spawn GPG process for verifying payload.".to_owned(),
            )
            .into()),
        }
    }

    pub fn encrypt(&self, plain: String, recipient: String) -> Result<Vec<u8>> {
        let mut child = Command::new("gpg")
            .arg(format!("--homedir={}", &self.gpg_path))
            .arg("--encrypt")
            .arg("-r")
            .arg(recipient)
            .arg("--always-trust")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .expect("Could not read from child process.");
            stdin.write_all(plain.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(ErrorKind::RuntimeError(format!(
                "Could not encrypt secret. Error: [{}]: {}",
                output.status,
                String::from_utf8(output.stderr)?
            ))
            .into());
        };
        println!("{:?}", output);
        Ok(output.stdout)
    }

    pub fn decrypt(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        let mut child = Command::new("gpg")
            .arg(format!("--homedir={}", &self.gpg_path))
            .arg("--decrypt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(secret.as_slice())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(ErrorKind::RuntimeError(format!(
                "Could not decrypt secret. Error: [{}]: {}",
                output.status,
                String::from_utf8(output.stderr)?
            ))
            .into());
        };
        Ok(output.stdout)
    }
}

pub fn handle(command: &ArgMatches, gpg_path: String) -> Result<()> {
    let gpg_manager = GpgManager::new(gpg_path)?;
    match command.subcommand() {
        ("owner", Some(subcommand)) => match subcommand.subcommand_name() {
            Some("add") => {
                let mut gpg_key = String::new();
                let _ = stdout().flush();
                stdin()
                    .read_to_string(&mut gpg_key)
                    .map(|_| gpg_manager.import_key(gpg_key))??;
            }
            _ => println!("got nothing"),
        },
        _ => println!("got nothing"),
    }
    Ok(())
}

fn extract_mail_from_uid(raw_str: Option<&str>) -> Option<String> {
    match raw_str {
        Some(uid_str) => {
            let expr = Regex::new(
                r#"^(.*)[<\["(]((?:[\w\d]+[.%-]?)+@(?:[[:alnum:]-]+)+(?:\.[a-z]{2,}){0,2}?)[)"\]>]$"#,
            ).unwrap();
            match expr.captures(uid_str) {
                Some(matches) => {
                    if matches.len() == 3usize {
                        return Some(matches.get(2).unwrap().as_str().to_string());
                    }
                    None
                }
                _ => None,
            }
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mails() {
        assert_eq!(
            extract_mail_from_uid(Some("283ujsdafj; [p'wae0- <fkbr@kuci.de>")),
            Some("fkbr@kuci.de".to_owned())
        );
        assert_eq!(
            extract_mail_from_uid(Some("Smörebröt Olsen <smoere-bloed.toppi@kuci.co.uk>")),
            Some("smoere-bloed.toppi@kuci.co.uk".to_owned())
        );
        assert_eq!(
            extract_mail_from_uid(Some("<no.name@aol.com>")),
            Some("no.name@aol.com".to_owned())
        );
    }
}
