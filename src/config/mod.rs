use dirs;
use errors::*;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;
use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CulperConfig {
    pub me: UserConfig,
    pub targets: Option<Vec<TargetConfig>>,
    pub owners: Option<Vec<UserConfig>>,
    pub admins: Option<Vec<UserConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserConfig {
    pub id: String,
    pub email: String,
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
        let config = self.read_string_to_config(&raw_toml)?;
        self.config = Some(config.clone());
        Ok(config)
    }

    pub fn add_target(&mut self, host: &str, id: &str) -> Result<()> {
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
            None => Err(ErrorKind::RuntimeError("Config is not set.".to_owned()).into()),
        }
    }

    pub fn update(&mut self, new_config: CulperConfig) {
        self.config = Some(new_config);
    }

    pub fn write(&self) -> Result<()> {
        match &self.config {
            Some(config) => {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&self.path)?
                    .write_all(toml::to_string(&config)?.as_bytes())?;
                Ok(())
            }
            None => Err(ErrorKind::RuntimeError("No config available to write.".to_owned()).into()),
        }
    }

    fn read_string_to_config(&self, string: &str) -> Result<CulperConfig> {
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
        me: UserConfig { email, id },
        targets: None,
        owners: None,
        admins: None,
    };
    File::create(config_path)?.write_all(toml::to_string(&config)?.as_bytes())?;
    Ok(())
}

pub mod gpg;

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut config_reader = ConfigReader::new(Some("./culper.toml")).unwrap();

        config_reader.update(CulperConfig {
            me: UserConfig {
                email: "overwrite@mail.de".to_owned(),
                id: "87654321".to_owned(),
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

    #[test]
    fn cleanup() {
        ::duct::cmd!("rm", "-rf", ".culper.toml")
            .run()
            .expect("This test should only fail if one of the previous test failed");
    }
}
