extern crate base64;
extern crate clap;
extern crate crypto;
extern crate rand;
extern crate serde_yaml;

use clap::{App, Arg, SubCommand};
// use base64::{decode, encode};
// use rand::prelude::*;
// use rand::OsRng;

fn main() {
    let matches = App::new("culper")
        .version("0.1.0")
        .author("Max Kiehnscherf")
        .about("Embed crypted values in your yaml")
        .subcommand(
            SubCommand::with_name("encrypt").arg(
                Arg::with_name("value")
                    .short("n")
                    .long("value")
                    .multiple(true)
                    .required(true)
                    .takes_value(true)
            ),
        ).get_matches();

  match matches.subcommand() {
    ("encrypt", Some(sub)) => {
      let vals: Vec<&str> = sub.values_of("value").unwrap().collect();
      for s in vals.into_iter() {
        println!("{}", s);
      };
    },
    _ => println!("lol")
  }
}

mod aes;
mod yaml;
