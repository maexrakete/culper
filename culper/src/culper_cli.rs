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
            SubCommand::with_name("setup")
                .about("Start setup for culper.")
                .arg(
                    Arg::with_name("name")
                        .long("name")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .display_order(10)
                .about("Decrypts a message"),
        )
        .subcommand(
            SubCommand::with_name("target")
                .subcommand(
                    SubCommand::with_name("add").setting(AppSettings::AllowExternalSubcommands),
                )
                .subcommand(
                    SubCommand::with_name("remove").setting(AppSettings::AllowExternalSubcommands),
                )
                .subcommand(SubCommand::with_name("list")),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .display_order(20)
                .about("Encrypts a message"),
        )
}
