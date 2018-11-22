use base64::{decode, encode};
use errors::*;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum EncryptionFormat {
    GPG_PUB_KEY,
}

impl EncryptionFormat {
    pub fn as_str(&self) -> String {
        match self {
            &EncryptionFormat::GPG_PUB_KEY => String::from("GPG_PUB_KEY"),
        }
    }
    pub fn from_str(value: &String) -> Result<EncryptionFormat> {
        match value.as_ref() {
            "GPG_PUB_KEY" => Ok(EncryptionFormat::GPG_PUB_KEY),
            _ => Err(ErrorKind::RuntimeError(format!(
                "Unknown encryption format given: {}",
                value
            ))
            .into()),
        }
    }
}

pub struct UnsealedVault {
    pub plain_secret: String,
    pub format: EncryptionFormat,
}

pub trait SealableVault {
    fn seal<F>(self, f: &F) -> Result<SealedVault>
    where
        F: Fn(UnsealedVault) -> Result<SealedVault>;
}

impl UnsealedVault {
    pub fn new(plain_secret: String, format: EncryptionFormat) -> UnsealedVault {
        UnsealedVault {
            plain_secret: plain_secret,
            format: format,
        }
    }
}

impl SealableVault for UnsealedVault {
    fn seal<F>(self, f: &F) -> Result<SealedVault>
    where
        F: Fn(UnsealedVault) -> Result<SealedVault>,
    {
        f(self)
    }
}

pub struct SealedVault {
    pub secret: Vec<u8>,
    pub format: EncryptionFormat,
}

pub trait OpenableVault {
    fn unseal<F>(self, f: &F) -> Result<UnsealedVault>
    where
        F: Fn(SealedVault) -> Result<UnsealedVault>;
    fn to_string(&self) -> String;
}

impl SealedVault {
    pub fn new(secret: Vec<u8>, format: EncryptionFormat) -> SealedVault {
        SealedVault {
            secret: secret,
            format: format,
        }
    }
}

impl OpenableVault for SealedVault {
    fn unseal<F>(self, f: &F) -> Result<UnsealedVault>
    where
        F: Fn(SealedVault) -> Result<UnsealedVault>,
    {
        f(self)
    }

    fn to_string(&self) -> String {
        format!("CULPER.{}.{}", self.format.as_str(), encode(&self.secret),)
    }
}

pub trait VaultHandler {
    fn encrypt(&self, UnsealedVault) -> Result<SealedVault>;
    fn decrypt(&self, SealedVault) -> Result<UnsealedVault>;
}

pub fn parse(value: &String) -> Result<SealedVault> {
    let value_list: Vec<&str> = value.split('.').collect();
    match value_list.as_slice() {
        ["CULPER", encryption_format, secret_bytes] => Ok(SealedVault::new(
            decode(secret_bytes)?,
            EncryptionFormat::from_str(&encryption_format.to_string())?,
        )),
        _ => Err("Could not parse string".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_encrypt() {
        let nuclear_codes = UnsealedVault::new(
            "zerozerozerozero".to_string(),
            EncryptionFormat::GPG_PUB_KEY,
        );
        let secret_nuclear_codes = nuclear_codes
            .seal(&|vault: UnsealedVault| {
                let secret = vault.plain_secret.chars().map(|c| match c {
                    'A'...'M' | 'a'...'m' => ((c as u8) + 13),
                    'N'...'Z' | 'n'...'z' => ((c as u8) - 13),
                    _ => c as u8,
                });

                Ok(SealedVault::new(secret.collect(), vault.format))
            })
            .unwrap();
        assert_eq!(
            "mrebmrebmrebmreb",
            String::from_utf8(secret_nuclear_codes.secret).unwrap()
        );
    }
}
