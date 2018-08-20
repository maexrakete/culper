use serde_yaml::Value;

pub fn traverse_node<'a>(
    value: &'a mut Value,
    node_tree: Vec<&str>,
) -> Result<&'a mut Value, String> {
    match node_tree.split_first() {
        Some((head, tail)) if tail.len() > 0 => match value
            .as_mapping_mut()
            .unwrap()
            .get_mut(&Value::String(head.to_string()))
        {
            Some(result) => traverse_node(result, tail.to_vec()),
            None => Err(format!("Key `{}` not found", head)),
        },
        Some((_, tail)) if tail.len() == 0 => Ok(value),
        _ => Err("Unknown Error".to_owned()),
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
        Some((last, _)) => match traverse_node(value, node_tree) {
            Ok(node) => replace(node, last.to_string(), replace_str),
            Err(e) => println!("{}", e),
        },
        None => println!("..."),
    }
}