extern crate serde_yaml;

use std::fs::File;
use std::io::prelude::*;

fn main() {
    let mut file = File::open("./debug.yml").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let mut yml: serde_yaml::Value = serde_yaml::from_str(&contents).unwrap();
    let path = "services.whoami.environment.DB_PASSWORD"
        .split('.')
        .collect();
    yaml::replace_value(&mut yml, path, String::from("lol"));
    println!("{}", serde_yaml::to_string(&yml).unwrap())
}

mod yaml;
