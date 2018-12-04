use clap::ArgMatches;
use config::ConfigReader;
use errors::*;
use gpg::GpgManager;
use server::SetupData;
use url::Url;

pub fn handle(
    subcommand: &'static ArgMatches,
    gpg_path: String,
    config_path: String,
) -> Result<()> {
    match subcommand.subcommand() {
        ("add", Some(subcommand)) => {
            let maybe_domain = Url::parse(subcommand.subcommand().0)?;

            if let Some(token) = subcommand.value_of("as_admin") {
                let gpg_manager = GpgManager::new(&gpg_path)?;
                let mut config_reader = ConfigReader::new(Some(&config_path))?;
                config_reader.read()?;
                let maybe_domain = Url::parse(subcommand.subcommand().0)?;
                let config = config_reader.config.unwrap();
                let pubkey = gpg_manager.pubkey_for_id(&config.me.id)?;
                let domain = format!("{}/public/pubkey.asc", maybe_domain.as_str());
                let client = reqwest::Client::new();

                client
                    .post(&domain)
                    .header("x-setup-key", token)
                    .json(&SetupData {
                        email: config.me.email.to_owned(),
                        pubkey: pubkey,
                    })
                    .build()?;
            } else {
                import_target(maybe_domain.as_str(), &gpg_path, &config_path)?;
            };
        }
        ("remove", _) => unimplemented!(),
        _ => unimplemented!(),
    };
    Ok(())
}

fn import_target(target: &str, gpg_path: &str, config_path: &str) -> Result<()> {
    reqwest::get(&format!("{}/public/pubkey.asc", target))
        .map_err(|_| ErrorKind::RuntimeError("no idea what's happening".to_owned()).into())
        .and_then(move |mut response| {
            println!("{:?}", response);
            let gpg_manager = GpgManager::new(&gpg_path)?;

            gpg_manager
                .import_key(&response.text()?)
                .map_err(|_| ErrorKind::RuntimeError("no idea what's happening".to_owned()))
                .map(|pubkey_id| {
                    let mut config_reader = ConfigReader::new(Some(&config_path))?;
                    println!("Importing remote key");
                    config_reader.read()?;
                    config_reader.add_target(&target, &pubkey_id)?;
                    config_reader.write()?;
                    Ok(())
                })?
        })
}
