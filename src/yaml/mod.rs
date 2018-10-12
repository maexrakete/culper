use errors::*;
use serde_yaml::{Mapping, Value};

pub fn find_node<'a>(value: &'a mut Value, node_tree: Vec<&str>) -> Result<&'a mut Value> {
    match node_tree.split_first() {
        Some((head, tail)) if tail.len() > 0 => match value
            .as_mapping_mut()
            .unwrap()
            .get_mut(&Value::String(head.to_string()))
        {
            Some(result) => find_node(result, tail.to_vec()),
            None => Err(ErrorKind::RuntimeError(format!("Key `{}` not found", head)).into()),
        },
        Some((_, tail)) if tail.len() == 0 => Ok(value),
        _ => Err(ErrorKind::RuntimeError("Unknown Error".to_owned()).into()),
    }
}

fn replace(value: &mut Value, key: String, replace: String) {
    if value.is_mapping() {
        let mapping = value.as_mapping_mut().unwrap();
        mapping.remove(&Value::String(key.clone()));
        mapping.insert(Value::String(String::from(key)), Value::String(replace));
    }
}

pub fn replace_value(value: &mut Value, node_tree: Vec<&str>, replace_str: String) {
    match node_tree.clone().split_last() {
        Some((last, _)) => match find_node(value, node_tree) {
            Ok(node) => replace(node, last.to_string(), replace_str),
            Err(e) => println!("{}", e),
        },
        None => println!("..."),
    }
}

pub fn traverse_yml<'a, F>(value: &'a Mapping, f: &F) -> Result<Mapping>
where
    F: Fn(&mut String) -> Result<Option<String>>,
{
    let mut new_yml: Mapping = Mapping::new();

    for entry in value.into_iter() {
        match entry {
            (Value::String(key), Value::String(s)) => {
                let new_value = f(&mut s.to_owned())?.unwrap_or(s.to_owned());
                new_yml.insert(Value::String(key.to_owned()), Value::String(new_value));
            }
            (Value::String(key), Value::Mapping(map)) => {
                let new_mapping = traverse_yml(&map, f)?;
                new_yml.insert(Value::String(key.to_owned()), Value::Mapping(new_mapping));
            }
            (Value::String(key), Value::Sequence(seq)) => {
                new_yml.insert(Value::String(key.to_owned()), Value::Sequence(seq.clone()));
            }
            (Value::String(key), Value::Number(num)) => {
                new_yml.insert(Value::String(key.to_owned()), Value::Number(num.clone()));
            }
            (Value::String(key), Value::Bool(boolean)) => {
                new_yml.insert(Value::String(key.to_owned()), Value::Bool(boolean.clone()));
            }
            _ => (),
        };
    }
    Ok(new_yml)
}
