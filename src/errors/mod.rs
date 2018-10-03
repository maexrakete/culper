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
}
