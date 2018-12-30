use failure::ResultExt;
use sequoia::openpgp::serialize::Serialize;
use sequoia::openpgp::TPK;
use time::now_utc;

pub struct AdminService {
    admin_id: i64,
    conn: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
}

impl AdminService {
    pub fn new(
        conn: r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>,
    ) -> Result<AdminService, failure::Error> {
        let admin_id = conn.query_row("SELECT id FROM stores WHERE name='admins'", &[], |row| {
            row.get(0)
        })?;
        Ok(AdminService { admin_id, conn })
    }

    pub fn import(&self, label: &str, tpk: TPK) -> Result<(), failure::Error> {
        let mut blob = vec![];
        tpk.serialize(&mut blob)?;

        let last_key_id = self
            .conn
            .execute(
                "INSERT INTO keys (fingerprint, key, created, update_at) VALUES(?1, ?2, ?3, ?4)",
                &[
                    &tpk.fingerprint().to_hex(),
                    &blob,
                    &now_utc().to_timespec(),
                    &now_utc().to_timespec(),
                ],
            )
            .and_then(|_| Ok(self.conn.last_insert_rowid()))?;

        self.conn.execute(
            "INSERT INTO bindings (store, label, key, created) VALUES(?1, ?2, ?3, ?4)",
            &[
                &self.admin_id,
                &label,
                &last_key_id,
                &now_utc().to_timespec(),
            ],
        )?;

        for (_, key) in tpk.keys() {
            let keyid = key
                .fingerprint()
                .to_keyid()
                .as_u64()
                .context("Computed keyid is invalid")?;
            let r = self.conn.execute(
                "INSERT INTO key_by_keyid (keyid, key) VALUES (?1, ?2)",
                &[&(keyid as i64), &last_key_id],
            );

            // The mapping might already be present.  This is not an error.
            match r {
                Err(rusqlite::Error::SqliteFailure(f, e)) => match f.code {
                    // Already present.
                    rusqlite::ErrorCode::ConstraintViolation => Ok(()),
                    // Raise otherwise.
                    _ => Err(rusqlite::Error::SqliteFailure(f, e)),
                },
                Err(e) => Err(e),
                Ok(_) => Ok(()),
            }?;
        }
        Ok(())
    }
}
