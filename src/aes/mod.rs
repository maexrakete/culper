extern crate crypto;
extern crate rand;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer};
use errors::*;
use rand::prelude::*;
use rand::OsRng;
use std::io::{stdin, stdout, Write};

// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result: Result<BufferResult> = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .map(|res| res)
            .map_err(|_| {
                ErrorKind::RuntimeError("Encrypting the given string failed.".to_owned()).into()
            });

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .map(|res| res)
            .map_err(|_| {
                ErrorKind::RuntimeError("Decrypting the given payload failed.".to_owned())
            });

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(final_result)
}

fn derive_key(password: String, salt: &[u8]) -> [u8; 64] {
    let mut crypted: [u8; 64] = [0; 64];
    let scrypt_params = crypto::scrypt::ScryptParams::new(14, 8, 1);
    crypto::scrypt::scrypt(password.as_bytes(), &salt, &scrypt_params, &mut crypted);
    crypted
}

fn password_prompt() -> Result<String> {
    eprint!("Enter password for encryption: ");
    let _ = stdout().flush();

    let mut password = String::new();
    stdin().read_line(&mut password)?;
    Ok(password)
}

fn create_iv() -> [u8; 16] {
    let mut iv: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut iv);
    iv
}

pub fn build_vault_payload(secret: String) -> Result<([u8; 16], [u8; 64])> {
    password_prompt().and_then(|pw| {
        let iv = create_iv();
        let key = derive_key(pw.to_owned(), &iv);
        Ok((iv, key))
    })
}
