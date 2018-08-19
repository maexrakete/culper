extern crate serde_yaml;
extern crate crypto;
extern crate rand;
extern crate base64;

use rand::prelude::*;
use rand::distributions::Alphanumeric;
use base64::{encode, decode};

fn main() {
  let mut rng = thread_rng();
  let iv: String = rng.sample_iter(&Alphanumeric).take(16).collect();
  match aes::encrypt("geheim".to_owned().as_bytes(), "password".to_owned().as_bytes(), iv.as_bytes()) {
    Ok(a) => {
      let crypted = encode(a.as_slice());
      assert_eq!(decode(&crypted).unwrap(), a);
      println!("success!");
    },
    Err(_) => println!("something's fishy")
  };
}

mod yaml;
mod aes;
