use failure::Error;
use serde_yaml::{Mapping, Value};

pub fn traverse_yml<'a, F>(value: &'a Mapping, f: &F) -> Result<Mapping, Error>
where
    F: Fn(&mut String) -> Result<Option<String>, Error>,
{
    let mut new_yml: Mapping = Mapping::new();

    for entry in value.into_iter() {
        match entry {
            (Value::String(key), Value::String(s)) => {
                let new_value = f(&mut s.to_owned())?.unwrap_or_else(|| s.to_owned());
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
                new_yml.insert(Value::String(key.to_owned()), Value::Bool(*boolean));
            }
            _ => (),
        };
    }
    Ok(new_yml)
}
