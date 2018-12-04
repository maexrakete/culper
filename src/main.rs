#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]

extern crate base64;
#[macro_use]
extern crate clap;
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
extern crate duct;
#[macro_use]
extern crate lazy_static;
extern crate futures;
extern crate parking_lot;
extern crate reqwest;
extern crate rocket_contrib;
extern crate url;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use config::{ConfigReader, CulperConfig};
use errors::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use std::str;
use vault::{EncryptionFormat, OpenableVault, SealableVault, UnsealedVault, VaultHandler};

lazy_static! {
    static ref matches: ArgMatches<'static> = app().get_matches();
}

fn app<'a>() -> App<'a, 'a> {
    App::new("culper")
        .version(crate_version!())
        .author("Max Kiehnscherf")
        .about("Embed crypted values in your yaml")
        .arg(
            Arg::with_name("config")
                .long("config_file")
                .help("Sets path to config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gpg_path")
                .long("gpg_path")
                .help("Sets path to gpg folder")
                .takes_value(true),
        )
        .subcommand(SubCommand::with_name("encrypt"))
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
        .subcommand(
            SubCommand::with_name("target").subcommand(
                SubCommand::with_name("add")
                    .arg(
                        Arg::with_name("as_admin")
                            .long("as_admin")
                            .takes_value(true),
                    )
                    .setting(AppSettings::AllowExternalSubcommands),
            ),
        )
        .subcommand(SubCommand::with_name("server"))
        .subcommand(
            SubCommand::with_name("setup").arg(
                Arg::with_name("server")
                    .long("server")
                    .help("Generate server settings")
                    .takes_value(false),
            ),
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
        file.read_to_string(&mut contents).or_else(|_| {
            Err(ErrorKind::RuntimeError("Could not parse result to YAML.".to_owned()).into())
        })
    })?;

    serde_yaml::from_str::<serde_yaml::Value>(&contents).or_else(|_| {
        Err(ErrorKind::RuntimeError("Could not parse result to YAML.".to_owned()).into())
    })
}

fn run() -> Result<()> {
    let gpg_path = match matches.value_of("gpg_path") {
        Some(gpg) => gpg.to_owned(),
        None => get_gpg_path()?,
    };

    let config_path = match matches.value_of("config") {
        Some(config) => config.to_owned(),
        None => get_config_path()?,
    };

    match &matches.subcommand() {
        ("encrypt", _) => {
            let config = ConfigReader::new(matches.value_of("config"))?.read()?;
            let encrypted_value = encrypt_value(&config, &gpg_path)?;
            println!(
                "{}",
                format!(
                    r#"
            Replace the desired key with this value:

{}
            "#,
                    encrypted_value
                )
            );
        }
        ("decrypt", Some(sub)) => {
            let config = ConfigReader::new(matches.value_of("config"))?.read()?;
            let ifile = sub.value_of("file").unwrap(); // clap handles this;
            let mut yml = load_yml(ifile.to_string())?;
            let replacefn = |val: &mut String| match vault::parse(val) {
                Ok(d) => match d.format {
                    EncryptionFormat::GPG_PUB_KEY => {
                        let vault_handler = gpg::PubKeyVaultHandler::new(
                            &config.me.id,
                            &config
                                .clone()
                                .targets
                                .unwrap_or_else(|| vec![])
                                .into_iter()
                                .map(|target| target.id)
                                .collect::<Vec<String>>(),
                            &gpg_path,
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
            let mut config_reader = ConfigReader::new(matches.value_of("config"))?;
            server::run(&mut config_reader, &gpg_path)?;
        }
        ("gpg", subcommand) => {
            gpg::handle(subcommand.unwrap(), &gpg_path)?;
        }
        ("target", subcommand) => client::target::handle(
            subcommand.unwrap(),
            gpg_path.to_owned(),
            config_path.to_owned(),
        )?,
        ("setup", Some(settings)) => {
            if settings.is_present("server") {
                setup::server_setup(&gpg_path, &config_path)?;
            } else {
                setup::setup(&gpg_path, &config_path)?;
            }
        }
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
    ::std::process::exit(0);
}

fn encrypt_value(culper_config: &CulperConfig, gpg_path: &str) -> Result<String> {
    eprint!("Enter value to encrypt: ");
    let _ = stdout().flush();
    let vault_handler = gpg::PubKeyVaultHandler::new(
        &culper_config.me.id,
        &culper_config
            .clone()
            .targets
            .unwrap_or_else(|| vec![])
            .into_iter()
            .map(|target| target.id)
            .collect::<Vec<String>>(),
        &gpg_path,
    );
    let mut value = String::new();
    stdin().read_line(&mut value)?;

    let vault = UnsealedVault::new(value.trim_right().to_owned(), EncryptionFormat::GPG_PUB_KEY)
        .seal(&|vault| vault_handler.encrypt(vault))?;

    Ok(vault.to_string())
}

fn get_gpg_path() -> Result<String> {
    let mut path = PathBuf::new();
    match dirs::home_dir() {
        Some(home) => path.push(home),
        None => path.push("./"),
    };
    path.push(".culper_gpg");
    path.to_str().map_or_else(
        || {
            Err(ErrorKind::RuntimeError(
                "There was an error deriving the gpg path. Consider passing one manually."
                    .to_owned(),
            )
            .into())
        },
        |path_str| Ok(path_str.to_owned()),
    )
}

fn get_config_path() -> Result<String> {
    let mut path = PathBuf::new();
    match dirs::home_dir() {
        Some(home) => path.push(home),
        None => path.push("./"),
    };
    path.push(".culper.toml");
    path.to_str().map_or_else(
        || {
            Err(ErrorKind::RuntimeError(
                "There was an error deriving the config path. Consider passing one manually."
                    .to_owned(),
            )
            .into())
        },
        |path_str| Ok(path_str.to_owned()),
    )
}

mod client;
mod config;
mod errors;
mod gpg;
mod server;
mod setup;
mod vault;
mod yaml;
