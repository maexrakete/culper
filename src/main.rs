extern crate base64;
extern crate clap;
extern crate crypto;
extern crate rand;
extern crate serde_yaml;

use clap::{App, Arg, SubCommand};
use std::io::{stdin,stdout,Write};
use base64::{encode};
use rand::prelude::*;
use rand::distributions::Alphanumeric;
use culper_drop::{CulperDrop, EncryptionFormat};
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let matches = App::new("culper")
        .version("0.1.0")
        .author("Max Kiehnscherf")
        .about("Embed crypted values in your yaml")
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .help("Sets input file")
             .takes_value(true)
             .required(true)
        )
        .subcommand(
            SubCommand::with_name("encrypt").arg(
                Arg::with_name("value")
                    .short("v")
                    .long("value")
                    .help("Key value denotion of YAML-Path and value")
                    .multiple(true)
                    .required(true)
                    .takes_value(true)
            ),
        ).get_matches();

  let ifile = matches.value_of("file").unwrap();
  if !Path::new(ifile).exists() {
    panic!("File not found")
  }

  let mut file = File::open(ifile).expect("Could not open input file");
  let mut contents = String::new();
  file.read_to_string(&mut contents).expect("Could not read file contents");
  let mut yml: serde_yaml::Value = serde_yaml::from_str(&contents).expect("Could not parse file content");

  match matches.subcommand() {
    ("encrypt", Some(sub)) => {
      eprint!("Enter password for encryption: ");
      let _ = stdout().flush();

      let mut password = String::new();
      if stdin().read_line(&mut password).is_ok() {
        let vals: Vec<&str> = sub.values_of("value").unwrap().collect();
        for s in vals {
          eprint!("Enter value for {} to encrypt: ", s);
          let _ = stdout().flush();

          let mut value = String::new();
          if stdin().read_line(&mut value).is_ok() {
            let drop = make_culper_drop(s, &password).expect("Could not build drop.");
            yaml::replace_value(&mut yml, s.split(".").collect(), drop.as_str());
          }
        }
      }
    },
    _ => println!("nothing") // clap handles this
  }
  println!("{}", serde_yaml::to_string(&yml).unwrap())
}

fn make_culper_drop(plain: &str, pass: &String) -> Result<CulperDrop, crypto::symmetriccipher::SymmetricCipherError>{
  let iv: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();
  match aes::encrypt(plain.as_bytes(), pass.as_bytes(), iv.as_bytes()) {
    Ok(a) => {
      Ok(CulperDrop::new(iv, encode(a.as_slice()), EncryptionFormat::CKM_AES_CBC_PAD))
    },
    Err(e) => Err(e)
  }
}

mod aes;
mod yaml;
mod culper_drop;
