use config::gpg;
use errors::*;
use iron::{Iron, Listening};
use mount::Mount;
use staticfile::Static;
use std::path::Path;

pub fn run() -> Result<Listening> {
    if !gpg::has_config() {
        println!("Creating GPG keys.");
        gpg::create_gpg_config()?;
    }

    let mut mount = Mount::new();
    mount.mount("/", Static::new(Path::new("public/pubkey.asc")));

    println!("Server running on http://localhost:1778");

    Iron::new(mount).http("127.0.0.1:1778").or_else(|e| {
        return Err(ErrorKind::RuntimeError(e.to_string()).into());
    })
}
