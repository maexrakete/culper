use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};

pub fn build() -> App<'static, 'static> {
    App::new("culper")
        .version("0.1.0")
        .about("")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(
            Arg::with_name("home")
                .value_name("DIRECTORY")
                .long("home")
                .help("Sets the home directory to use"),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .display_order(10)
                .about("Decrypts a message"),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .display_order(20)
                .about("Encrypts a message"),
        )
        .subcommand(
            SubCommand::with_name("store")
                .display_order(30)
                .about("Interacts with key stores")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(SubCommand::with_name("list").about("Lists keys in the store"))
                .subcommand(
                    SubCommand::with_name("add")
                        .about("Add a key identified by fingerprint")
                        .arg(
                            Arg::with_name("label")
                                .value_name("LABEL")
                                .required(true)
                                .help("Label to use"),
                        )
                        .arg(
                            Arg::with_name("fingerprint")
                                .value_name("FINGERPRINT")
                                .required(true)
                                .help("Key to add"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("import")
                        .about("Imports a key")
                        .arg(
                            Arg::with_name("label")
                                .value_name("LABEL")
                                .required(true)
                                .help("Label to use"),
                        )
                        .arg(
                            Arg::with_name("input")
                                .value_name("FILE")
                                .help("Sets the input file to use"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("export")
                        .about("Exports a key")
                        .arg(
                            Arg::with_name("label")
                                .value_name("LABEL")
                                .required(true)
                                .help("Label to use"),
                        )
                        .arg(
                            Arg::with_name("output")
                                .value_name("FILE")
                                .long("output")
                                .short("o")
                                .help("Sets the output file to use"),
                        )
                        .arg(
                            Arg::with_name("binary")
                                .long("binary")
                                .short("B")
                                .help("Don't ASCII-armor encode the OpenPGP data"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Deletes bindings or stores")
                        .arg(
                            Arg::with_name("the-store")
                                .long("the-store")
                                .help("Delete the selected store (change with --store)"),
                        )
                        .arg(
                            Arg::with_name("label")
                                .value_name("LABEL")
                                .help("Delete binding with this label"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("Lists key stores and known keys")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("stores")
                        .about("Lists key stores")
                        .arg(
                            Arg::with_name("prefix")
                                .value_name("PREFIX")
                                .help("List only stores with the given domain prefix"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("bindings")
                        .about("Lists all bindings in all key stores")
                        .arg(
                            Arg::with_name("prefix").value_name("PREFIX").help(
                                "List only bindings from stores with the given domain prefix",
                            ),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("keys").about("Lists all keys in the common key pool"),
                )
                .subcommand(SubCommand::with_name("log").about("Lists the server log")),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generate a new key")
                .arg(
                    Arg::with_name("userid")
                        .value_name("EMAIL")
                        .long("userid")
                        .short("u")
                        .help("Primary user ID"),
                ),
        )
}
