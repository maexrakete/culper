use config;
use config::{ConfigReader, CulperConfig, UserConfig};
use errors::*;
use gpg::GpgManager;
use parking_lot::RwLock;
use rocket::data::FromDataSimple;
use rocket::http::Status;
use rocket::request::{FromRequest, Request};
use rocket::response::{Responder, Response};
use rocket::{Data, Outcome, State};
use rocket_contrib::json::Json;
use rocket_contrib::serve::StaticFiles;
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

struct SetupGuard(Option<String>);

enum SetupState {
    Success,
    Failure,
}

struct SetupResult(SetupState);

impl<'r> Responder<'r> for SetupResult {
    fn respond_to(self, _: &Request) -> rocket::response::Result<'r> {
        match self.0 {
            SetupState::Success => Response::build().status(Status::Ok).ok(),
            SetupState::Failure => Err(Status::Unauthorized),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for SetupGuard {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<SetupGuard, ()> {
        let maybe_auth_header = request.headers().get_one("x-setup-key");
        match maybe_auth_header {
            Some(auth_header) => Outcome::Success(SetupGuard(Some(auth_header.to_string()))),
            _ => Outcome::Failure((Status::Unauthorized, ())),
        }
    }
}

struct SignedRequest {
    pub body: String,
    pub signature: String,
}

impl FromDataSimple for SignedRequest {
    type Error = ();
    fn from_data(request: &Request, data: Data) -> rocket::data::Outcome<Self, ()> {
        let mut body = String::new();
        if data
            .open()
            .take(1_000_000)
            .read_to_string(&mut body)
            .is_err()
        {
            return Outcome::Failure((Status::InternalServerError, ()));
        }
        match request.headers().get_one("x-req-sig") {
            Some(signature) => Outcome::Success(SignedRequest {
                body,
                signature: signature.to_owned(),
            }),
            _ => Outcome::Failure((Status::Unauthorized, ())),
        }
    }
}
#[derive(Deserialize, Serialize, Debug)]
pub struct SetupData {
    pub email: String,
    pub pubkey: String,
}

fn extract_option_from_rwlock(state: &State<RwLock<Option<String>>>) -> Option<String> {
    match *state.read() {
        Some(ref value) => Some(value.to_string()),
        None => None,
    }
}

fn update_culperconfig_with_admin(admin: &SetupData, gpg_config: &str) -> Result<()> {
    let gpg_manager = GpgManager::new(&gpg_config)?;
    match gpg_manager.import_key(&admin.pubkey) {
        Ok(val) => {
            let mut config_reader = ConfigReader::new(None)?;
            let mut config = config_reader.read()?;
            config.admins = match config.admins {
                Some(mut admins) => {
                    admins.push(UserConfig {
                        email: admin.email.to_string(),
                        id: val.to_owned(),
                    });
                    Some(admins)
                }
                None => Some(vec![UserConfig {
                    email: admin.email.to_owned(),
                    id: val.to_owned(),
                }]),
            };
            config_reader.update(config);
            config_reader.write()
        }
        Err(err) => Err(ErrorKind::RuntimeError(
            format!("Could not import gpg key. Error: {:?}", err).to_owned(),
        )
        .into()),
    }
}

#[allow(clippy::needless_pass_by_value)]
#[post("/registeradmin", data = "<admin_data>")]
fn register_admin(
    key: SetupGuard,
    secret_lock: State<RwLock<Option<String>>>,
    gpg_config: State<String>,
    admin_data: Json<SetupData>,
) -> Result<SetupResult> {
    let secret_key = extract_option_from_rwlock(&secret_lock);
    match (secret_key, key.0) {
        (Some(ref secret), Some(ref header)) => {
            if secret == header {
                update_culperconfig_with_admin(&admin_data, &gpg_config)?;
                let mut a = secret_lock.write();
                println!("Obtained lock, overwriting secret.");
                *a = None;
                Ok(SetupResult(SetupState::Success))
            } else {
                Ok(SetupResult(SetupState::Failure))
            }
        }
        _ => Ok(SetupResult(SetupState::Failure)),
    }
}

#[allow(clippy::needless_pass_by_value)]
#[post("/demo", data = "<body>")]
fn demo(body: SignedRequest, gpg_config: State<String>) -> Result<String> {
    let gpg_manager = GpgManager::new(&gpg_config.to_owned())?;
    gpg_manager.verify(&body.body, &body.signature)?;
    Ok(body.body)
}

pub fn run(config_reader: &mut ConfigReader, gpg_config: &str) -> Result<()> {
    if !config::gpg::has_config(&gpg_config) {
        config::gpg::create_gpg_server_config(gpg_config)?;

        let user_config = GpgManager::new(gpg_config)?.parse_private_key()?;
        config_reader.update(CulperConfig {
            me: user_config,
            admins: None,
            owners: None,
            targets: None,
        });

        config_reader.write()?;
    } else {
        config_reader.read()?;
    }

    let config = match &config_reader.config {
        Some(val) => Ok(val.to_owned()),
        None => Err(ErrorKind::RuntimeError(
            r#"
          For some reason the presence of a config file was assumed but none found.
          This might be the result of an error during initialization. Consider
          removing your existing configuration or create one manually.

          Normally this should not happen.
        "#
            .to_string(),
        )),
    };

    let secret = if config?.admins.is_none() {
        let secret = Uuid::new_v4().to_simple().to_string();
        println!(
            "{}",
            format!(
                r#"
        ######################################
        #            SETUP SECRET            #
        #  {}  #
        ######################################
        "#,
                secret
            )
        );
        Some(secret)
    } else {
        None
    };
    rocket::ignite()
        .manage(RwLock::new(secret))
        .manage(gpg_config.to_owned())
        .mount("/public", StaticFiles::from(Path::new("public")))
        .mount("/", routes![register_admin, demo])
        .launch();

    Ok(())
}
