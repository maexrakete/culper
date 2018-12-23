use failure::{self, ResultExt};
use rpassword;
use std::collections::HashMap;
use std::io;

extern crate sequoia;
use sequoia::core::Context;
use sequoia::openpgp::packet::{key::SecretKey, Key, Signature, PKESK, SKESK};
use sequoia::openpgp::parse::stream::{
    DecryptionHelper, Decryptor, Secret, VerificationHelper, VerificationResult,
};
use sequoia::openpgp::parse::PacketParser;
use sequoia::openpgp::{Fingerprint, KeyID, Result, TPK};
use sequoia::store;

use super::{dump::PacketDumper, VHelper};

struct Helper<'a> {
    vhelper: VHelper<'a>,
    secret_keys: HashMap<KeyID, Key>,
    key_identities: HashMap<KeyID, Fingerprint>,
    key_hints: HashMap<KeyID, String>,
    dumper: Option<PacketDumper>,
    hex: bool,
    pass: Pass,
}

enum Pass {
    UnencryptedKey(usize),
    EncryptedKey(usize),
    Passwords,
}

impl Default for Pass {
    fn default() -> Self {
        Pass::UnencryptedKey(0)
    }
}

impl<'a> Helper<'a> {
    fn new(
        ctx: &'a Context,
        store: &'a mut store::Store,
        signatures: usize,
        tpks: Vec<TPK>,
        secrets: Vec<TPK>,
        dump: bool,
        hex: bool,
    ) -> Self {
        let mut keys: HashMap<KeyID, Key> = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        for tsk in secrets {
            let can_encrypt = |_: &Key, sig: Option<&Signature>| -> bool {
                if let Some(sig) = sig {
                    sig.key_flags().can_encrypt_at_rest()
                        || sig.key_flags().can_encrypt_for_transport()
                } else {
                    false
                }
            };

            let hint = match tsk.userids().nth(0) {
                Some(uid) => format!("{} ({})", uid.userid(), tsk.fingerprint().to_keyid()),
                None => format!("{}", tsk.fingerprint().to_keyid()),
            };

            if can_encrypt(tsk.primary(), tsk.primary_key_signature()) {
                let id = tsk.fingerprint().to_keyid();
                keys.insert(id.clone(), tsk.primary().clone());
                identities.insert(id.clone(), tsk.fingerprint());
                hints.insert(id, hint.clone());
            }

            for skb in tsk.subkeys() {
                let key = skb.subkey();
                if can_encrypt(key, skb.binding_signature()) {
                    let id = key.fingerprint().to_keyid();
                    keys.insert(id.clone(), key.clone());
                    identities.insert(id.clone(), tsk.fingerprint());
                    hints.insert(id, hint.clone());
                }
            }
        }

        Helper {
            vhelper: VHelper::new(ctx, store, signatures, tpks),
            secret_keys: keys,
            key_identities: identities,
            key_hints: hints,
            dumper: if dump || hex {
                Some(PacketDumper::new(false))
            } else {
                None
            },
            hex: hex,
            pass: Pass::default(),
        }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        self.vhelper.get_public_keys(ids)
    }
    fn check(&mut self, sigs: Vec<Vec<VerificationResult>>) -> Result<()> {
        self.vhelper.check(sigs)
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn mapping(&self) -> bool {
        self.hex
    }

    fn inspect(&mut self, pp: &PacketParser) -> Result<()> {
        if let Some(dumper) = self.dumper.as_mut() {
            dumper.packet(
                &mut io::stderr(),
                pp.recursion_depth() as usize,
                pp.header().clone(),
                pp.packet.clone(),
                pp.map().map(|m| m.clone()),
                None,
            )?;
        }
        Ok(())
    }

    fn get_secret(&mut self, pkesks: &[&PKESK], skesks: &[&SKESK]) -> Result<Option<Secret>> {
        loop {
            self.pass = match self.pass {
                Pass::UnencryptedKey(ref mut i) => {
                    while let Some(pkesk) = pkesks.get(*i) {
                        *i += 1;
                        let keyid = pkesk.recipient();
                        let key = if let Some(key) = self.secret_keys.get(keyid) {
                            key
                        } else {
                            continue;
                        };

                        if let Some(SecretKey::Unencrypted { ref mpis }) = key.secret() {
                            return Ok(Some(Secret::Asymmetric {
                                identity: self.key_identities.get(keyid).unwrap().clone(),
                                key: key.clone(),
                                secret: mpis.clone(),
                            }));
                        }
                    }

                    Pass::EncryptedKey(0)
                }

                Pass::EncryptedKey(ref mut i) => {
                    while let Some(pkesk) = pkesks.get(*i) {
                        *i += 1;
                        let keyid = pkesk.recipient();
                        let key = if let Some(key) = self.secret_keys.get(keyid) {
                            key
                        } else {
                            continue;
                        };

                        if key.secret().map(|s| s.is_encrypted()).unwrap_or(false) {
                            loop {
                                let p = rpassword::prompt_password_stderr(&format!(
                                    "Enter password to decrypt key {}: ",
                                    self.key_hints.get(keyid).unwrap()
                                ))?
                                .into();

                                if let Ok(mpis) = key.secret().unwrap().decrypt(key.pk_algo(), &p) {
                                    return Ok(Some(Secret::Asymmetric {
                                        identity: self.key_identities.get(keyid).unwrap().clone(),
                                        key: key.clone(),
                                        secret: mpis,
                                    }));
                                }

                                eprintln!("Bad password.");
                            }
                        }
                    }

                    Pass::Passwords
                }

                Pass::Passwords => {
                    if skesks.is_empty() {
                        return Err(failure::err_msg("No key to decrypt message"));
                    }
                    return Ok(Some(Secret::Symmetric {
                        password: rpassword::prompt_password_stderr(
                            "Enter password to decrypt message: ",
                        )?
                        .into(),
                    }));
                }
            }
        }
    }
}

pub fn decrypt(
    ctx: &Context,
    store: &mut store::Store,
    input: &mut io::Read,
    output: &mut io::Write,
    signatures: usize,
    tpks: Vec<TPK>,
    secrets: Vec<TPK>,
    dump: bool,
    hex: bool,
) -> Result<()> {
    let helper = Helper::new(ctx, store, signatures, tpks, secrets, dump, hex);
    let mut decryptor = Decryptor::from_reader(input, helper).context("Decryption failed")?;

    io::copy(&mut decryptor, output)
        .map_err(|e| {
            if e.get_ref().is_some() {
                // Wrapped failure::Error.  Recover it.
                failure::Error::from_boxed_compat(e.into_inner().unwrap())
            } else {
                // Plain io::Error.
                e.into()
            }
        })
        .context("Decryption failed")?;

    let helper = decryptor.into_helper();
    if let Some(dumper) = helper.dumper.as_ref() {
        dumper.flush(&mut io::stderr())?;
    }
    helper.vhelper.print_status();
    return Ok(());
}
