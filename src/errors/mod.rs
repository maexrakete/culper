error_chain!{
  errors {
          UserError(description: String) {
              description(&description)
              display("User error: '{}'", description)
          }
          InternalError(description: String) {
              description(&description)
              display("Internal error: '{}'", description)
          }
          RuntimeError(description: String) {
              description(&description)
              display("Internal error: '{}'", description)
          }
  }
  foreign_links {
    Io(::std::io::Error);
    Toml(::toml::de::Error);
    TomlSerializing(::toml::ser::Error);
    Utf8(::std::string::FromUtf8Error);
    Regex(::regex::Error);
    SerdeYml(::serde_yaml::Error);
    Base64Decode(::base64::DecodeError);
    UrlParse(::url::ParseError);
  }
}
