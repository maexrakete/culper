use actix_web::{client, HttpMessage};
use clap::ArgMatches;
use config::ConfigReader;
use errors::*;
use futures::future::Future;
use gpg::GpgManager;
use url::Url;

pub fn handle(subcommand: &ArgMatches, gpg_path: String, config_path: String) -> Result<()> {
    match subcommand.subcommand() {
        ("add", Some(subcommand)) => {
            let maybe_domain = Url::parse(subcommand.subcommand().0)?;
            actix::run(|| {
                client::get(format!("{}/public/pubkey.asc", maybe_domain.as_str())) // <- Create request builder
                    .finish()
                    .unwrap()
                    .send() // <- Send http request
                    .map_err(|err| println!("Error: {:?}", err))
                    .and_then(move |response| {
                        response
                            .body()
                            .map_err(|err| println!("Error: {:?}", err))
                            .and_then(|body| {
                                let gpg_manager = GpgManager::new(&gpg_path)
                                    .map_err(|err| println!("Error: {:?}", err))?;
                                gpg_manager
                                    .import_key(
                                        &String::from_utf8(body.to_vec())
                                            .map_err(|err| println!("Error: {:?}", err))?,
                                    )
                                    .and_then(|pubkey_id| {
                                        let mut config_reader =
                                            ConfigReader::new(Some(&config_path))?;
                                        config_reader.read()?;
                                        config_reader.add_target(&maybe_domain.as_str(), &pubkey_id)
                                    })
                                    .map_err(|err| println!("Error: {:?}", err))?;
                                Ok(())
                            })
                            .poll()?;
                        Ok(())
                    })
            });
        }
        ("remove", _) => unimplemented!(),
        _ => (),
    };
    Ok(())
}
