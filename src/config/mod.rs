use dirs;
use errors::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CulperConfig {
    pub me: UserConfig,
    pub targets: Option<()>,
    pub owners: Option<Vec<UserConfig>>,
    pub admins: Option<Vec<UserConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct ConfigReader {
    pub path: PathBuf,
    pub config: Option<CulperConfig>,
}

impl ConfigReader {
    pub fn new(raw_config_path: Option<&str>) -> Result<ConfigReader> {
        let config_path = match raw_config_path {
            Some(val) => PathBuf::from(val),
            None => get_config_path()?,
        };
        Ok(ConfigReader {
            path: config_path,
            config: None,
        })
    }

    pub fn read(&mut self) -> Result<CulperConfig> {
        if !&self.path.exists() {
            return Err(ErrorKind::UserError(
                "culper.toml not found. Create one or pass the --config_file option.".to_owned(),
            )
            .into());
        }
        let mut raw_toml = String::new();
        File::open(&self.path)?.read_to_string(&mut raw_toml)?;
        let config = self.read_string_to_config(raw_toml)?;
        self.config = Some(config.clone());
        Ok(config)
    }

    pub fn update(&mut self, new_config: CulperConfig) {
        self.config = Some(new_config);
    }

    pub fn write(&self) -> Result<()> {
        match &self.config {
            Some(config) => {
                File::create(&self.path)?.write(toml::to_string(&config)?.as_bytes())?;
                Ok(())
            }
            None => Err(ErrorKind::RuntimeError("No config available to write.".to_owned()).into()),
        }
    }

    fn read_string_to_config(&self, string: String) -> Result<CulperConfig> {
        let parsed_toml: CulperConfig = toml::from_str(&string)?;
        Ok(parsed_toml)
    }
}

fn get_config_path() -> Result<PathBuf> {
    let mut path = PathBuf::new();
    match dirs::home_dir() {
        Some(home) => path.push(home),
        None => path.push("./"),
    };
    path.push(".culper.toml");
    Ok(path)
}

pub fn create(email: String, id: String, config_path: String) -> Result<()> {
    let config = CulperConfig {
        me: UserConfig {
            email: email,
            id: id,
        },
        targets: None,
        owners: None,
        admins: None,
    };
    File::create(config_path)?.write(toml::to_string(&config)?.as_bytes());
    Ok(())
}

pub mod gpg;
