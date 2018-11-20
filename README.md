# culper
[![Build Status](https://travis-ci.org/maexrakete/culper.svg?branch=master)](https://travis-ci.org/maexrakete/culper)[![Coverage Status](https://coveralls.io/repos/github/maexrakete/culper/badge.svg?branch=master)](https://coveralls.io/github/maexrakete/culper?branch=master)

culper makes your secrets versionable. culper stores and reads gpg encrypted secrets in your yaml-file. This allows you to safely check your yaml files into your version control and distribute deployment-files between developers without exposing the secret.

## Idea

The idea behind culper stems from a very specific use-case: I want to store my docker-compose files in some kind of version control without exposing the secrets in them.
To achieve this, the server part of culper generates a pair of gpg keys and makes its public key accessible via http. The client part then uses the public key to encrypt
the secret and store it in your yaml file.

During the deployment phase culper then uses gpg to decrypt the values and you can start your application.

Culper comes with following advantages:
* Passwordless en- & decryption of secrets
* Stateless deployment of your services (everything is in your yaml)
* *Coming Soon:* Need secrets for multiple endpoints? Easy, just declare them as recipients

## Todo

- [ ] Improve & document Setup flow
- [ ] build dockerfile for server 
- [ ] security audit (e.g. fix passing request signature directly to `cmd!`) 
- [ ] more tests!
- [ ] add commands for adding and removing users
- [ ] Improve README
- [ ] Logo
