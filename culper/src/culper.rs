/// A command-line frontend for Sequoia.
extern crate clap;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate prettytable;
extern crate promptly;
extern crate rpassword;
extern crate tempfile;
extern crate time;
#[macro_use]
extern crate lazy_static;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate sequoia;
extern crate serde_yaml;
extern crate toml;

use failure::ResultExt;
use prettytable::{Cell, Row, Table};
use promptly::prompt;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::process::exit;

use self::vault::{OpenableVault, SealableVault};
use clap::ArgMatches;
use failure::Error;
use sequoia::core::Context;
use sequoia::openpgp::parse::Parse;
use sequoia::openpgp::serialize::Serialize;
use sequoia::openpgp::{armor, TPK};
use sequoia::store::{LogIter, Store};
use std::path::PathBuf;

lazy_static! {
    static ref matches: ArgMatches<'static> = culper_cli::build().get_matches();
    static ref config_reader: config::ConfigReader =
        config::ConfigReader::new(matches.value_of("home"));
    static ref priv_key: String = read_priv_key(
        home_dir(matches.value_of("home")),
        matches.value_of("priv_key")
    )
    .expect("Could not read private key file.");
}

fn read_priv_key(home_dir: PathBuf, maybe_priv_key: Option<&str>) -> Result<String, Error> {
    let mut path = PathBuf::new();
    match maybe_priv_key {
        // key is not at home location or named differently
        Some(priv_key_path) => path.push(priv_key_path),
        // key is at home location with standard name
        None => {
            path.push(home_dir);
            path.push("privkey.asc");
        }
    };

    let mut content = String::new();
    File::open(&path)
        .context(format!(
            "Could not open private key {}",
            path.clone().to_str().unwrap_or_default()
        ))?
        .read_to_string(&mut content)
        .context(format!(
            "Could not read private key {}",
            path.clone().to_str().unwrap_or_default()
        ))?;

    Ok(content)
}

fn home_dir(maybe_home: Option<&str>) -> PathBuf {
    let mut path = PathBuf::new();
    match maybe_home {
        Some(given_home) => path.push(given_home),
        None => match dirs::home_dir() {
            Some(home) => path.push(home),
            None => path.push("./"),
        },
    }
    path.push(".culper");
    path
}

fn open_or_stdin(f: Option<&str>) -> Result<Box<io::Read>, failure::Error> {
    match f {
        Some(f) => Ok(Box::new(
            File::open(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(io::stdin())),
    }
}

fn create_or_stdout(f: Option<&str>, force: bool) -> Result<Box<io::Write>, failure::Error> {
    use promptly::prompt_default;

    match f {
        None => Ok(Box::new(io::stdout())),
        Some(p) if p == "-" => Ok(Box::new(io::stdout())),
        Some(f) => {
            let p = Path::new(f);
            let path_ok = force
                || !p.exists()
                || prompt_default(format!("{} exists already. Overwrite?", f), false);

            if path_ok {
                Ok(Box::new(
                    OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(f)
                        .context("Failed to create output file")?,
                ))
            } else {
                eprintln!("Cannot continue");
                exit(1);
            }
        }
    }
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
fn help_warning(arg: &str) {
    if arg == "help" {
        eprintln!(
            "Warning: \"help\" is not a subcommand here.  \
             Did you mean --help?"
        );
    }
}

fn real_main() -> Result<(), failure::Error> {
    let ctx = Context::configure("localhost")
        .home(home_dir(matches.value_of("home")))
        .build()?;
    let store_name = "default";
    match matches.subcommand() {
        ("encrypt", Some(m)) => {
            let mut output = create_or_stdout(m.value_of("output"), false)?;
            let mut output = if !m.is_present("binary") {
                Box::new(armor::Writer::new(&mut output, armor::Kind::Message, &[])?)
            } else {
                output
            };

            let store = Store::open(&ctx, store_name).context("Failed to open the store")?;
            let mut recipients = vec![];

            let mut priv_tpk = TPK::from_bytes(priv_key.as_bytes())?;

            let pair = priv_tpk.primary_mut();
            match pair.secret_mut() {
                Some(secret) => {
                    if secret.is_encrypted() {
                        let password = rpassword::prompt_password_stderr(
                            "Enter password to decrypt private key: ",
                        )
                        .context("Could not read password from stdin.")?;

                        secret.decrypt_in_place(
                            sequoia::openpgp::constants::PublicKeyAlgorithm::RSAEncryptSign,
                            &password.into(),
                        )
                    } else {
                        Ok(())
                    }
                }
                None => Err(format_err!("Could not access secret key")),
            }?;

            let priv_tpk = vec![priv_tpk];
            recipients.extend(priv_tpk.clone());

            eprint!("Enter value to decrypt: ");
            let value: String = prompt("");
            let vault =
                vault::UnsealedVault::new(value.to_owned(), vault::EncryptionFormat::GPG_KEY);
            let sealed_vault = vault.seal(&move |vault: vault::UnsealedVault| {
                let secret_bytes = vault.plain_secret.as_bytes();
                let data =
                    commands::encrypt(secret_bytes.to_vec(), recipients.clone(), priv_tpk.clone())?;

                Ok(vault::SealedVault::new(data, vault.format))
            })?;

            println!("{}", sealed_vault.to_string());
        }
        ("store", Some(m)) => {
            let store = Store::open(&ctx, store_name).context("Failed to open the store")?;

            match m.subcommand() {
                ("list", Some(_)) => {
                    list_bindings(&store, "localhost", store_name)?;
                }
                ("import", Some(m)) => {
                    let label = m.value_of("label").unwrap();
                    help_warning(label);
                    let mut input = open_or_stdin(m.value_of("input"))?;
                    let tpk = TPK::from_reader(&mut input)?;
                    store.import(label, &tpk)?;
                }
                ("export", Some(m)) => {
                    let tpk = store.lookup(m.value_of("label").unwrap())?.tpk()?;

                    let mut output = create_or_stdout(m.value_of("output"), false)?;
                    let mut output = if !m.is_present("binary") {
                        Box::new(armor::Writer::new(
                            &mut output,
                            armor::Kind::PublicKey,
                            &[],
                        )?)
                    } else {
                        output
                    };

                    tpk.serialize(&mut output)?;
                }
                ("delete", Some(m)) => {
                    if m.is_present("label") == m.is_present("the-store") {
                        eprintln!("Please specify either a label or --the-store.");
                        exit(1);
                    }

                    if m.is_present("the-store") {
                        store.delete().context("Failed to delete the store")?;
                    } else {
                        let binding = store
                            .lookup(m.value_of("label").unwrap())
                            .context("Failed to get key")?;
                        binding.delete().context("Failed to delete the binding")?;
                    }
                }
                _ => {
                    eprintln!("No store subcommand given.");
                    exit(1);
                }
            }
        }
        ("keygen", Some(m)) => {
            use sequoia::openpgp::armor::{Kind, Writer};
            use sequoia::openpgp::serialize::Serialize;
            use sequoia::openpgp::tpk::{CipherSuite, TPKBuilder};

            let mut builder = TPKBuilder::default();

            // User ID
            match m.value_of("userid") {
                Some(uid) => {
                    builder = builder.add_userid(uid);
                }
                None => {
                    eprintln!("No user ID given, using direct key signature");
                }
            }

            builder = builder.set_cipher_suite(CipherSuite::RSA3k);
            builder = builder.add_signing_subkey();
            builder = builder.add_encryption_subkey();

            // Generate the key
            let (tpk, _rev) = builder.generate()?;
            let tsk = tpk.into_tsk();

            {
                let w = create_or_stdout(None, false)?;
                let mut w = Writer::new(w, Kind::SecretKey, &[])?;
                tsk.serialize(&mut w)?;
            }
        }
        _ => {
            eprintln!("No subcommand given.");
            exit(1);
        }
    }

    return Ok(());
}

fn list_bindings(store: &Store, domain: &str, name: &str) -> Result<(), failure::Error> {
    if store.iter()?.count() == 0 {
        println!(
            "No label-key bindings in the \"{}/{}\" store.",
            domain, name
        );
        return Ok(());
    }

    println!("Domain: {:?}, store: {:?}:", domain, name);

    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row!["label", "fingerprint"]);
    for (label, fingerprint, _) in store.iter()? {
        table.add_row(Row::new(vec![
            Cell::new(&label),
            Cell::new(&fingerprint.to_string()),
        ]));
    }
    table.printstd();
    Ok(())
}

fn print_log(iter: LogIter, with_slug: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    let mut head = row!["timestamp", "message"];
    if with_slug {
        head.insert_cell(1, Cell::new("slug"));
    }
    table.set_titles(head);

    for entry in iter {
        let mut row = row![&format_time(&entry.timestamp), &entry.short()];
        if with_slug {
            row.insert_cell(1, Cell::new(&entry.slug));
        }
        table.add_row(row);
    }

    table.printstd();
}

fn format_time(t: &time::Timespec) -> String {
    time::strftime("%F %H:%M", &time::at(*t)).unwrap() // Only parse errors can happen.
}

fn main() {
    if let Err(e) = real_main() {
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}

mod commands;
mod config;
mod culper_cli;
mod vault;
