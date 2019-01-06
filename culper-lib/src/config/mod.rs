use dirs;
use failure::{Context, Error, Fail, ResultExt};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;
use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CulperConfig {
    pub targets: Option<Vec<TargetConfig>>,
    pub owners: Option<Vec<UserConfig>>,
    pub admins: Option<Vec<UserConfig>>,
    pub me: UserConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub fingerprint: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetConfig {
    pub id: String,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct ConfigReader {
    pub path: PathBuf,
    pub config: Option<CulperConfig>,
}

impl ConfigReader {
    pub fn new(raw_config_path: Option<&str>) -> ConfigReader {
        let config_path = match raw_config_path {
            Some(val) => PathBuf::from(val),
            None => get_config_path(),
        };

        ConfigReader {
            path: config_path,
            config: None,
        }
    }

    pub fn read(&mut self) -> Result<CulperConfig, Error> {
        if !&self.path.exists() {
            return Err(format_err!(
                "{} not found. Create one or pass the --config_file option.",
                &self
                    .path
                    .to_str()
                    .expect("Failed converting path to string.")
            ));
        }

        let mut raw_toml = String::new();
        File::open(&self.path)
            .context("Could not open configuration file")?
            .read_to_string(&mut raw_toml)
            .context("Could not read configuration file")?;

        let config = self.read_string_to_config(&raw_toml)?;
        self.config = Some(config.clone());
        Ok(config)
    }

    pub fn add_target(&mut self, host: &str, id: &str) -> Result<(), Error> {
        match &mut self.config {
            Some(ref mut config) => match config.targets {
                None => {
                    config.targets = Some(vec![TargetConfig {
                        host: host.to_owned(),
                        id: id.to_owned(),
                    }]);
                    Ok(())
                }
                Some(ref mut targets) => {
                    targets.push(TargetConfig {
                        host: host.to_owned(),
                        id: id.to_owned(),
                    });

                    Ok(())
                }
            },
            None => Err(format_err!("Config is not set.")),
        }
    }

    pub fn update(&mut self, new_config: CulperConfig) -> &mut Self {
        self.config = Some(new_config);
        self
    }

    pub fn write(&self) -> Result<(), Error> {
        match &self.config {
            Some(config) => {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&self.path)?
                    .write_all(toml::to_string(&config)?.as_bytes())?;
                Ok(())
            }
            None => Err(format_err!("No config available to write.")),
        }
    }

    fn read_string_to_config(&self, string: &str) -> Result<CulperConfig, Error> {
        let parsed_toml: CulperConfig = toml::from_str(&string)?;
        Ok(parsed_toml)
    }
}

fn get_config_path() -> PathBuf {
    let mut path = PathBuf::new();
    match dirs::home_dir() {
        Some(home) => path.push(home),
        None => path.push("./"),
    };
    path.push(".culper.toml");
    path
}

pub fn create(name: String, fingerprint: String, config_path: String) -> Result<(), Error> {
    let config = CulperConfig {
        me: UserConfig { name, fingerprint },
        targets: None,
        owners: None,
        admins: None,
    };
    File::create(config_path)?.write_all(toml::to_string(&config)?.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn can_create_config() {
        create(
            "test@test.de".to_owned(),
            "12345678".to_owned(),
            "./culper.toml".to_owned(),
        )
        .unwrap();
        assert!(Path::new("./culper.toml").exists());
    }

    #[test]
    fn can_update_existing_config() {
        let mut config_reader = ConfigReader::new(Some("./culper.toml"));

        config_reader.update(CulperConfig {
            me: UserConfig {
                name: "overwrite@mail.de".to_owned(),
                fingerprint: "1234 5678 ABCD ETC".to_owned(),
            },
            targets: None,
            owners: None,
            admins: None,
        });

        config_reader
            .add_target("www.test.de", "alskjdflsajfd")
            .unwrap();
        config_reader.write().unwrap();

        let mut file = OpenOptions::new().read(true).open("./culper.toml").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, ::toml::to_string(&config_reader.config).unwrap())
    }
}
