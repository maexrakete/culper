use aes;
use base64::{decode, encode};
use rand::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{OsRng};
use crypto;
use std::iter::repeat;

#[derive(Debug)]
pub enum EncryptionFormat {
    CKM_AES_CBC_PAD,
}

impl EncryptionFormat {
    pub fn as_str(&self) -> String {
        match self {
            &EncryptionFormat::CKM_AES_CBC_PAD => String::from("AES_CBC_PAD"),
        }
    }
}

#[derive(Debug)]
pub struct Vault {
    pub pass: String,
    pub format: EncryptionFormat,
    salt: Option<String>,
    sealed: bool
}

impl Vault {
    pub fn new(pass: String, format: EncryptionFormat, salt: Option<String>, sealed: bool) -> Vault {
        Vault {
            pass: pass,
            format: format,
            salt: salt,
            sealed: sealed
        }
    }

    pub fn new_unsealed(pass: String) -> Vault {
      Vault {
        pass: pass,
        format: EncryptionFormat::CKM_AES_CBC_PAD,
        salt: None,
        sealed: false
      }
    }

    pub fn as_str(self) -> String {
        return format!(
            "CULPER.{}.{}.{}",
            self.format.as_str(),
            self.salt.unwrap_or("<NONE>".to_owned()),
            self.pass
        );
    }

    pub fn parse(value: &String) -> Result<Vault, ()> {
        let value_list: Vec<&str> = value.split('.').collect();
        match value_list.as_slice() {
            ["CULPER", _, "<NONE>", pass] => Ok(Self::new(
              pass.to_string(),
              EncryptionFormat::CKM_AES_CBC_PAD,
              None,
              false
            )),
            ["CULPER", _, crypt_salt, crypt_pass] => Ok(Self::new(
                crypt_pass.to_string(),
                EncryptionFormat::CKM_AES_CBC_PAD,
                Some(crypt_salt.to_string()),
                true
            )),
            _ => Err(()),
        }
    }

  fn derive_key(&self, password: String, salt: &String) -> Vec<u8> {
    let mut crypted: Vec<u8> = vec![0; 64];
    let scrypt_params = crypto::scrypt::ScryptParams::new(14, 8, 1);
    crypto::scrypt::scrypt(password.as_bytes(), &salt.to_owned().as_bytes(), &scrypt_params, &mut crypted);
    crypted
  }

    pub fn seal(&self, password: String) -> Result<Vault, ()> {
      let mut iv: [u8; 16] = [0; 16];
      let mut rng = OsRng::new().ok().unwrap();
      let salt_ref = &self.salt.;
      let salt = salt_ref.as_ref();

      println!("{:?}", salt);
      let derived_key = self.derive_key(password, &salt.unwrap().to_owned());
      rng.fill_bytes(&mut iv);

      match aes::encrypt(self.pass.as_bytes(), derived_key.as_slice(), &iv) {
        Ok(payload) => {
          Ok(Self::new(
              encode(payload.as_slice()),
              EncryptionFormat::CKM_AES_CBC_PAD,
              Some(encode(&iv)),
              true
          ))},
          Err(e) => Err(()),
      }
    }

  pub fn unseal(self, password: String) -> Result<Vault, crypto::symmetriccipher::SymmetricCipherError> {
    let payload_bytes = decode(&self.pass).expect("Sometinh wrong with the pass");
    let salt = self.salt.as_ref().expect("Unseal could not access salt").clone();

    let iv_bytes = decode(&salt).expect("Something wrong with the salt.");
    let derived_key = self.derive_key(password, &salt.to_owned());

    match aes::decrypt(payload_bytes.as_slice(), derived_key.as_slice(), iv_bytes.as_slice()) {
      Ok(payload) => {
          Ok(Self::new(
              String::from_utf8(payload).expect("String conversion did not work"),
              EncryptionFormat::CKM_AES_CBC_PAD,
              None,
              false
          ))
      },
      Err(e) => Err(e)
    }
  }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_encrypt() {
      let secret = "i actually liked the prequels.".to_string();
      let password = "jarjarrocks".to_string();
      let vault = Vault::new_unsealed(secret);
      let sealed = vault.seal(password);

      assert!(sealed.is_ok());
    }

    // #[test]
    // fn can_decrypt() {
    //   let secret = "i actually liked the prequels.";
    //   let password = "jarjarrocks".to_string();
    //   let vault = Vault::new_unsealed(secret.to_owned());

    //   let sealed = vault.seal(&password).unwrap();
    //   let unsealed = sealed.unseal(&password);

    //   assert!(unsealed.is_ok());
    //   assert_eq!(unsealed.unwrap().pass, secret.to_owned());
    // }

    // #[test]
    // fn can_decrypt_from_string() {
    //   let secret = "i actually liked the prequels.";
    //   let password = "jarjarrocks".to_string();
    //   let vault = Vault::new_unsealed(secret.to_owned());

    //   let sealed = vault.seal(&password).unwrap().as_str();

    //   let unsealed = Vault::parse(&sealed).unwrap().unseal(&password).unwrap();

    //   assert_eq!(unsealed.pass, secret.to_owned());
    // }
}
