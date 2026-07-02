//! Read-only extraction of saved logins from Chromium `Login Data` → `logins`.
//!
//! Saved passwords are encrypted with the same `os_crypt` v10 scheme as cookies
//! but WITHOUT the SHA256(host) prefix. This module currently only *reads* them
//! into a portable form; rebuilding the full `Login Data` schema on restore is
//! deferred (most session state lives in cookies, which snapshots do normalize).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::oscrypt::LocalCrypt;
use crate::portable::PortableLogin;

pub fn login_data_path(udd: &Path) -> PathBuf {
    udd.join("Default").join("Login Data")
}

/// Read + decrypt saved logins. Returns empty if the DB is absent.
pub fn read(db_path: &Path, crypt: &LocalCrypt) -> Result<Vec<PortableLogin>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db_path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value, password_value, signon_realm FROM logins",
    )?;
    let rows = stmt.query_map([], |r| {
        let origin_url: String = r.get(0)?;
        let username_value: String = r.get(1)?;
        let enc: Vec<u8> = r.get(2)?;
        let signon_realm: String = r.get(3).unwrap_or_default();
        let password_value = crypt
            .decrypt_secret(&enc)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        Ok(PortableLogin {
            origin_url,
            username_value,
            password_value,
            signon_realm,
        })
    })?;
    let mut out = Vec::new();
    for l in rows {
        out.push(l?);
    }
    Ok(out)
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn login_read_decrypts() {
        let dir = std::env::temp_dir().join(format!("shardx-lg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("Login Data");
        let crypt = LocalCrypt::with_key(vec![0x11; 16]);

        // Minimal logins table sufficient for our read query.
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, \
             password_value BLOB, signon_realm TEXT);",
        )
        .unwrap();
        let enc = crypt.encrypt_secret(b"s3cret");
        conn.execute(
            "INSERT INTO logins VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["https://site.test/", "alice", enc, "https://site.test/"],
        )
        .unwrap();
        drop(conn);

        let got = read(&db, &crypt).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].username_value, "alice");
        assert_eq!(got[0].password_value, "s3cret");
    }
}
