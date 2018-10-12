# culper
[![Build Status](https://travis-ci.org/maexrakete/culper.svg?branch=master)](https://travis-ci.org/maexrakete/culper)[![Coverage Status](https://coveralls.io/repos/github/maexrakete/culper/badge.svg?branch=master)](https://coveralls.io/github/maexrakete/culper?branch=master)

culper stores and reads gpg encrypted secrets in your yaml-file. This allows you to safely check your yaml files into your version control and distribute deployment-files between developers without exposing the secret.

# Usage
culper comes in two flavors: client and server.

The culper server generates its own gpg config and exposes its public key via http. The culper client then embedds the secret encrypted with its own and the servers pubkey into your yaml.
When you now embedd culper in your deploy tool you can decrypt the secrets and start your server.
