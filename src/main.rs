extern crate serde_yaml;

use serde_yaml::Value;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let mut file = File::open("./debug.yml").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let mut yml: serde_yaml::Value = serde_yaml::from_str(&contents).unwrap();
    let path = "services.whoami.lol".split('.').collect();
    find_node(&mut yml, path);
    println!("{}", serde_yaml::to_string(&yml).unwrap())
}

fn find_node<'a>(value: &'a mut Value, node_tree: Vec<&str>) {
    match node_tree.split_first() {
        Some((head, tail)) if tail.len() > 0 => {
            println!("Check `{}`", head);
            match value
                .as_mapping_mut()
                .unwrap()
                .get_mut(&Value::String(head.to_string()))
            {
                Some(mut result) => {
                    find_node(&mut result, tail.to_vec());
                }
                None => println!("Key {} not found", head),
            }
        }
        Some((head, tail)) if tail.len() == 0 => {
            if value.is_mapping() {
                let mut mapping = value.as_mapping_mut().unwrap();
                mapping.remove(&Value::String(head.to_string()));
                mapping.insert(
                    Value::String(head.to_string()),
                    Value::String(String::from("replacetext")),
                );
            }
        }
        _ => println!("This should not happen"),
    }
}
