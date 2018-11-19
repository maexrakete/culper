#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]

extern crate base64;
extern crate clap;
extern crate crypto;
extern crate dirs;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate toml;
#[macro_use]
extern crate error_chain;
extern crate regex;
extern crate uuid;
#[macro_use]
extern crate rocket;
extern crate parking_lot;
extern crate rocket_contrib;
#[macro_use]
extern crate duct;

use clap::{App, Arg, SubCommand};
use config::{ConfigReader, CulperConfig};
use errors::*;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};
use std::str;
use vault::{EncryptionFormat, OpenableVault, SealableVault, UnsealedVault, VaultHandler};

fn app<'a>() -> App<'a, 'a> {
    App::new("culper")
        .version("0.1.0")
        .author("Max Kiehnscherf")
        .about("Embed crypted values in your yaml")
        .arg(
            Arg::with_name("config")
                .long("config")
                .help("Sets path to config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gpg_path")
                .long("gpg_path")
                .help("Sets path to gpg folder")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .arg(
                    Arg::with_name("value")
                        .short("v")
                        .long("value")
                        .help("YAML path which should be encrypted")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("overwrite")
                        .short("o")
                        .long("overwrite")
                        .help("Overwrites input file")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("file")
                        .short("f")
                        .long("file")
                        .help("Sets input file")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt").arg(
                Arg::with_name("file")
                    .short("f")
                    .long("file")
                    .help("Sets input file")
                    .takes_value(true)
                    .required(true),
            ),
        )
        .subcommand(SubCommand::with_name("server"))
        .subcommand(
            SubCommand::with_name("setup")
                .arg(Arg::with_name("sever").help("Generate server settings")),
        )
        .subcommand(
            SubCommand::with_name("gpg")
                .subcommand(SubCommand::with_name("owner").subcommand(SubCommand::with_name("add")))
                .subcommand(
                    SubCommand::with_name("target").subcommand(SubCommand::with_name("add")),
                ),
        )
}

fn load_yml(file_path: String) -> Result<serde_yaml::Value> {
    let mut contents = String::new();
    let maybefile =
        File::open(file_path).chain_err(|| ErrorKind::RuntimeError("Can't open file".to_owned()));
    maybefile.and_then(|mut file| {
        file.read_to_string(&mut contents)
            .or(Err(ErrorKind::RuntimeError(
                "Could not parse result to YAML.".to_owned(),
            )
            .into()))
    })?;

    serde_yaml::from_str::<serde_yaml::Value>(&contents).or(Err(ErrorKind::RuntimeError(
        "Could not parse result to YAML.".to_owned(),
    )
    .into()))
}

fn run() -> Result<()> {
    let matches = app().get_matches();
    let gpg_path = match matches.value_of("gpg_path") {
        Some(val) => RefCell::new(Some(val.to_owned())),
        None => RefCell::new(None),
    };
    let config = ConfigReader::new(matches.value_of("config"))?.read()?;
    match &matches.subcommand() {
        ("encrypt", Some(sub)) => {
            let ifile = sub.value_of("file").unwrap(); // clap handles this;
            let mut yml = load_yml(ifile.to_string())?;
            let vals: &str = sub.value_of("value").unwrap();
            encrypt_yml(&mut yml, &vals, config, gpg_path.clone().into_inner())?;

            match sub.is_present("overwrite") {
                true => {
                    println!("Overwriting input file.");
                    let mut output = OpenOptions::new().write(true).open(ifile).unwrap();
                    write!(output, "{}", serde_yaml::to_string(&yml).unwrap());
                }
                false => println!("{}", serde_yaml::to_string(&yml).unwrap()),
            }
        }
        ("decrypt", Some(sub)) => {
            let ifile = sub.value_of("file").unwrap(); // clap handles this;
            let mut yml = load_yml(ifile.to_string())?;
            let replacefn = |val: &mut String| match vault::parse(val) {
                Ok(d) => match d.format {
                    EncryptionFormat::GPG_PUB_KEY => {
                        let vault_handler = gpg::PubKeyVaultHandler::new(
                            config.me.id.to_owned(),
                            gpg_path.clone().into_inner(),
                        );
                        let vault = d.unseal(&|vault| vault_handler.decrypt(vault))?;
                        Ok(Some(vault.plain_secret))
                    }
                },
                _ => Ok(None),
            };
            let uncrypted_yml = yaml::traverse_yml(&yml.as_mapping().unwrap(), &replacefn)?;
            println!("{}", serde_yaml::to_string(&uncrypted_yml)?)
        }
        ("server", _) => {
            server::run(config, gpg_path.clone().into_inner());
        }
        ("gpg", subcommand) => {
            gpg::handle(subcommand.unwrap(), gpg_path.clone().into_inner())?;
        }
        ("setup", settings) => match settings {
            Some(_) => setup::server_setup(gpg_path.clone().into_inner())?,
            None => setup::setup(gpg_path.clone().into_inner())?,
        },
        _ => println!("nothing"), // clap handles this
    }
    Ok(())
}

fn main() {
    if let Err(ref e) = run() {
        println!("error: {}", e);

        for e in e.iter().skip(1) {
            println!("caused by: {}", e);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            println!("backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
}

fn encrypt_yml(
    yml: &mut serde_yaml::Value,
    path: &str,
    culper_config: CulperConfig,
    gpg_path: Option<String>,
) -> Result<()> {
    eprint!("Enter value for {} to encrypt: ", path);
    let _ = stdout().flush();
    let vault_handler = gpg::PubKeyVaultHandler::new(culper_config.me.id, gpg_path);
    let mut value = String::new();
    stdin().read_line(&mut value)?;

    let vault = UnsealedVault::new(value.trim_right().to_owned(), EncryptionFormat::GPG_PUB_KEY)
        .seal(&|vault| vault_handler.encrypt(vault))?;
    yaml::replace_value(yml, path.split(".").collect(), vault.to_string());

    Ok(())
}

mod aes;
mod config;
mod errors;
mod gpg;
mod server;
mod setup;
mod vault;
mod yaml;
