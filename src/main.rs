extern crate base64;
extern crate clap;
extern crate crypto;
extern crate rand;
extern crate serde_yaml;

use clap::{App, Arg, SubCommand};
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{stdin, stdout, Write};
use std::path::Path;
use std::str;
use vault::Vault;
fn app<'a>() -> App<'a,'a> {
  App::new("culper")
      .version("0.1.0")
      .author("Max Kiehnscherf")
      .about("Embed crypted values in your yaml")
      .arg(
          Arg::with_name("file")
              .short("f")
              .long("file")
              .help("Sets input file")
              .takes_value(true)
              .required(true),
      ).subcommand(
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
              ),
      ).subcommand(SubCommand::with_name("decrypt"))
}

fn main() {
    let matches = app().get_matches();

    let ifile = matches.value_of("file").unwrap(); // clap handles this;

    if !Path::new(ifile).exists() {
        panic!("File not found")
    }

    let mut file = File::open(ifile).expect("Could not open input file");
    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .expect("Could not read file contents");

    let mut yml: serde_yaml::Value =
        serde_yaml::from_str(&contents).expect("Could not parse file content");

    match matches.subcommand() {
        ("encrypt", Some(sub)) => {
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

fn make_vault(
    plain: &String,
    pass: String,
) -> Result<Vault, crypto::symmetriccipher::SymmetricCipherError> {
    Vault::new_unsealed(plain.to_owned()).seal(pass)
}

mod aes;
mod vault;
mod yaml;
