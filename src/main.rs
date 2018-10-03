extern crate base64;
extern crate clap;
extern crate crypto;
extern crate rand;
extern crate serde_yaml;
#[macro_use]
extern crate error_chain;

use clap::{App, Arg, SubCommand};
pub use errors::*;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};
use std::str;
use vault::Vault;

fn app<'a>() -> App<'a, 'a> {
    App::new("culper")
        .version("0.1.0")
        .author("Max Kiehnscherf")
        .about("Embed crypted values in your yaml")
        .subcommand(
            SubCommand::with_name("encrypt")
                .arg(
                    Arg::with_name("value")
                        .short("v")
                        .long("value")
                        .help("YAML path which should be encrypted")
                        .multiple(true)
                        .required(true)
                        .takes_value(true),
                ).arg(
                    Arg::with_name("overwrite")
                        .short("o")
                        .long("overwrite")
                        .help("Overwrites input file")
                        .conflicts_with("file")
                        .takes_value(false),
                ).arg(
                    Arg::with_name("file")
                        .short("f")
                        .long("file")
                        .help("Sets input file")
                        .takes_value(true)
                        .required(true),
                ),
        ).subcommand(
            SubCommand::with_name("decrypt").arg(
                Arg::with_name("file")
                    .short("f")
                    .long("file")
                    .help("Sets input file")
                    .takes_value(true)
                    .required(true),
            ),
        ).subcommand(SubCommand::with_name("server"))
}

fn load_yml(file_path: String) -> Result<serde_yaml::Value> {
    let mut contents = String::new();
    let maybefile =
        File::open(file_path).chain_err(|| ErrorKind::RuntimeError("Can't open file".to_owned()));
    maybefile.and_then(|mut file| {
        file.read_to_string(&mut contents)
            .or(Err(ErrorKind::RuntimeError(
                "Could not parse result to YAML.".to_owned(),
            ).into()))
    })?;

    serde_yaml::from_str::<serde_yaml::Value>(&contents).or(Err(ErrorKind::RuntimeError(
        "Could not parse result to YAML.".to_owned(),
    ).into()))
}

fn main() {
    let matches = app().get_matches();

    match matches.subcommand() {
        ("encrypt", Some(sub)) => {
            let ifile = matches.value_of("file").unwrap(); // clap handles this;
            let mut yml = load_yml(ifile.to_string()).expect("Could not load yml.");
            let vals: Vec<&str> = sub.values_of("value").unwrap().collect();
            encrypt_yml(&mut yml, &vals);

            match sub.is_present("overwrite") {
                true => {
                    println!("Overwriting input file.");
                    let mut output = OpenOptions::new().write(true).open(ifile).unwrap();
                    write!(output, "{}", serde_yaml::to_string(&yml).unwrap());
                }
                false => println!("{}", serde_yaml::to_string(&yml).unwrap()),
            }
        }
        ("decrypt", _) => {
            let ifile = matches.value_of("file").unwrap(); // clap handles this;
            let mut yml = load_yml(ifile.to_string()).expect("Could not load yml.");

            eprint!("Enter password for decryption: ");
            let _ = stdout().flush();
            let mut password = String::new();

            if stdin().read_line(&mut password).is_ok() {
                let replacefn = |val: &mut String| match Vault::parse(val) {
                    Ok(d) => {
                        let val = d
                            .unseal(password.to_owned())
                            .expect("Could not decrypt Vault:");

                        Some(val.pass.to_owned())
                    }
                    _ => None,
                };
                let uncrypted_yml = yaml::traverse_yml(&yml.as_mapping().unwrap(), &replacefn);
                println!("{}", serde_yaml::to_string(&uncrypted_yml).unwrap())
            }
        }
        ("server", _) => {
            server::run();
        }
        _ => println!("nothing"), // clap handles this
    }
}

fn encrypt_yml(yml: &mut serde_yaml::Value, values: &Vec<&str>) {
    eprint!("Enter password for encryption: ");
    let _ = stdout().flush();

    let mut password = String::new();
    if stdin().read_line(&mut password).is_ok() {
        for s in values {
            eprint!("Enter value for {} to encrypt: ", s);
            let _ = stdout().flush();

            let mut value = String::new();
            if stdin().read_line(&mut value).is_ok() {
                let trimmed_value = value.trim_right();
                let vault = make_vault(&trimmed_value.to_owned(), password.to_owned())
                    .expect("Could not build Vault.");
                yaml::replace_value(yml, s.split(".").collect(), vault.as_str());
            }
        }
    }
}

fn make_vault(plain: &String, pass: String) -> Result<Vault> {
    Ok(Vault::new_unsealed(plain.to_owned()).seal(pass)?)
}

mod aes;
mod errors;
mod server;
mod vault;
mod yaml;
