use serde_yaml::Value;

pub fn traverse_node<'a>(value: &'a mut Value, node_tree: Vec<&str>) -> Option<&'a mut Value> {
    match node_tree.split_first() {
        Some((head, tail)) if tail.len() > 0 => {
            match value
                .as_mapping_mut()
                .unwrap()
                .get_mut(&Value::String(head.to_string()))
            {
                Some(mut result) => {
                    traverse_node(&mut result, tail.to_vec())
                }
                None => None,
            }
        }
      Some((_, tail)) if tail.len() == 0 => Some(value),
        _ => None,
    }
}

fn replace(value: & mut Value, key: String, replace: String) {
    if value.is_mapping() {
        let mapping = value.as_mapping_mut().unwrap();
        mapping.remove(&Value::String(key.clone()));
        mapping.insert(
            Value::String(String::from(key)),
            Value::String(replace),
        );
    }
}

pub fn replace_value(value: & mut Value, node_tree: Vec<&str>, replace_str: String) {
  match node_tree.clone().split_last() {
    Some((last, _)) => {
      match traverse_node(value, node_tree) {
        Some(node) => replace(node, last.to_string(), replace_str),
        None => println!("...")
      }
    },
    None => println!("...")
  }
}
