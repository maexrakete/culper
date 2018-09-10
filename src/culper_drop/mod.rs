pub enum EncryptionFormat {
  CKM_AES_CBC_PAD
}

impl EncryptionFormat {
  pub fn as_str(&self) -> String {
    match self {
      &EncryptionFormat::CKM_AES_CBC_PAD => String::from("AES_CBC_PAD")
      }
  }
}

pub struct CulperDrop {
  salt: String,
  pass: String,
  format: EncryptionFormat
}

impl CulperDrop {
  pub fn new(salt: String, pass: String, format: EncryptionFormat) -> CulperDrop {
    CulperDrop {
      salt: salt,
      pass: pass,
      format: format,
    }
  }

  pub fn as_str(&self) -> String {
    return format!("CULPER.{}.{}.{}", self.format.as_str(), self.salt, self.pass)
  }

  pub fn parse(value: &String) {
    let value_list: Vec<&str> = value.split('.').collect();
    match value_list.as_slice() {
      ["CULPER", _, crypt_salt, crypt_pass] => println!("Seems to be valid format"),
      _ => println!("No valid format")
    };
  }
}
