use errors::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use toml;

#[derive(Deserialize, Debug)]
pub struct CulperConfig {
    pub client: ClientConfig,
}

#[derive(Deserialize, Debug)]
pub struct ClientConfig {
    pub gpg_folder: Option<PathBuf>,
}

pub struct ConfigReader {}

impl ConfigReader {
    pub fn read(&self, culper_config: PathBuf) -> Result<CulperConfig> {
        if !culper_config.exists() {
            return Err(ErrorKind::UserError(
                "culper.toml not found. Create one or pass the --config option.".to_owned(),
            ).into());
        }
        let mut raw_toml = String::new();
        File::open(culper_config)?.read_to_string(&mut raw_toml)?;

        Ok(self.read_string_to_config(raw_toml)?)
    }

    fn read_string_to_config(&self, string: String) -> Result<CulperConfig> {
        let parsed_toml: CulperConfig = toml::from_str(&string)?;
        Ok(parsed_toml)
    }
}

pub mod gpg;
