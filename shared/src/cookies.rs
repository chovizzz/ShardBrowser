//! Read/write a profile's Chromium `Cookies` SQLite DB (schema v24).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags};

use crate::oscrypt::LocalCrypt;
use crate::portable::PortableCookie;

const WIN_EPOCH_DELTA_SECS: i64 = 11_644_473_600;

fn chromium_to_unix_secs(micros: i64) -> f64 {
    micros as f64 / 1_000_000.0 - WIN_EPOCH_DELTA_SECS as f64
}
fn unix_to_chromium(secs: f64) -> i64 {
    ((secs + WIN_EPOCH_DELTA_SECS as f64) * 1_000_000.0) as i64
}
fn now_chromium() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    unix_to_chromium(now)
}

fn samesite_to_str(v: i64) -> &'static str {
    match v {
        0 => "None",
        1 => "Lax",
        2 => "Strict",
        _ => "unspecified",
    }
}
fn samesite_from_str(s: Option<&str>) -> i64 {
    match s.map(|x| x.to_ascii_lowercase()).as_deref() {
        Some("none") => 0,
        Some("lax") => 1,
        Some("strict") => 2,
        _ => -1,
    }
}

/// Resolve the Cookies DB path: prefer `Default/Network/Cookies` (Chromium ≥96),
/// fall back to `Default/Cookies`. For a fresh dir, writes under `Network/` when
/// that directory already exists.
pub fn cookies_db_path(udd: &Path) -> PathBuf {
    let net = udd.join("Default").join("Network").join("Cookies");
    if net.exists() {
        return net;
    }
    let primary = udd.join("Default").join("Cookies");
    if primary.exists() {
        return primary;
    }
    if udd.join("Default").join("Network").is_dir() {
        return net;
    }
    primary
}

/// Read + decrypt all cookies. Read-only (won't fight a running browser's WAL).
pub fn read(db_path: &Path, crypt: &LocalCrypt) -> Result<Vec<PortableCookie>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db_path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT host_key, name, value, encrypted_value, path, expires_utc, \
         is_secure, is_httponly, has_expires, samesite FROM cookies",
    )?;
    let rows = stmt.query_map([], |r| {
        let host: String = r.get(0)?;
        let name: String = r.get(1)?;
        let plain: String = r.get(2)?;
        let enc: Vec<u8> = r.get(3)?;
        let path: String = r.get(4)?;
        let expires_utc: i64 = r.get(5)?;
        let is_secure: i64 = r.get(6)?;
        let is_httponly: i64 = r.get(7)?;
        let has_expires: i64 = r.get(8)?;
        let samesite: i64 = r.get(9)?;
        Ok(PortableCookie {
            value: crypt.decrypt_cookie(&enc, &plain),
            domain: host,
            name,
            path,
            expires: if has_expires != 0 {
                Some(chromium_to_unix_secs(expires_utc))
            } else {
                None
            },
            secure: is_secure != 0,
            http_only: is_httponly != 0,
            same_site: Some(samesite_to_str(samesite).to_string()),
        })
    })?;
    let mut out = Vec::new();
    for c in rows {
        out.push(c?);
    }
    Ok(out)
}

/// Write cookies (v10-encrypted with `crypt`). Caller must ensure the profile
/// is stopped. Creates the DB + schema if missing.
pub fn write(db_path: &Path, crypt: &LocalCrypt, cookies: &[PortableCookie]) -> Result<usize> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    ensure_schema(&conn)?;

    let now = now_chromium();
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO cookies (\
             creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, \
             path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, \
             is_persistent, priority, samesite, source_scheme, source_port, \
             last_update_utc, source_type, has_cross_site_ancestor) \
             VALUES (?1, ?2, '', ?3, '', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, ?14, ?15, 0, 1)",
        )?;
        for c in cookies {
            let enc = crypt.encrypt_cookie(&c.domain, &c.value);
            let has_expires = c.expires.is_some();
            let expires_utc = c.expires.map(unix_to_chromium).unwrap_or(0);
            let source_scheme = if c.secure { 2 } else { 1 };
            let source_port = if c.secure { 443 } else { 80 };
            stmt.execute(params![
                now,
                c.domain,
                c.name,
                enc,
                c.path,
                expires_utc,
                c.secure as i64,
                c.http_only as i64,
                now,
                has_expires as i64,
                has_expires as i64,
                samesite_from_str(c.same_site.as_deref()),
                source_scheme,
                source_port,
                now,
            ])?;
        }
    }
    tx.commit()?;
    Ok(cookies.len())
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);\
         INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '24');\
         INSERT OR IGNORE INTO meta (key, value) VALUES ('last_compatible_version', '24');\
         CREATE TABLE IF NOT EXISTS cookies (\
            creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, \
            top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL, \
            encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, \
            is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, \
            has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL, \
            samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, source_port INTEGER NOT NULL, \
            last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL, \
            has_cross_site_ancestor INTEGER NOT NULL);\
         CREATE UNIQUE INDEX IF NOT EXISTS cookies_unique_index ON cookies (\
            host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port);",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(domain: &str, name: &str, value: &str) -> PortableCookie {
        PortableCookie {
            domain: domain.into(),
            name: name.into(),
            value: value.into(),
            path: "/".into(),
            expires: Some(4_102_444_800.0), // 2100-01-01
            secure: true,
            http_only: true,
            same_site: Some("Lax".into()),
        }
    }

    #[test]
    fn cookie_db_roundtrip() {
        let dir = std::env::temp_dir().join(format!("shardx-ck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("Cookies");
        let crypt = LocalCrypt::open(&dir).unwrap();

        let n = write(&db, &crypt, &[sample(".example.com", "sid", "abc"), sample(".x.io", "t", "9")]).unwrap();
        assert_eq!(n, 2);

        let got = read(&db, &crypt).unwrap();
        assert_eq!(got.len(), 2);
        let sid = got.iter().find(|c| c.name == "sid").unwrap();
        assert_eq!(sid.value, "abc");
        assert_eq!(sid.domain, ".example.com");
        assert!(sid.secure && sid.http_only);
    }

    // Prove the snapshot re-key path at the DB level: write under key A, read
    // back, re-write under key B, read under B → same values.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn cookie_db_rekey() {
        let dir = std::env::temp_dir().join(format!("shardx-ckrk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_a = LocalCrypt::with_key(vec![0xAA; 16]);
        let key_b = LocalCrypt::with_key(vec![0xBB; 16]);

        let db_a = dir.join("A");
        write(&db_a, &key_a, &[sample(".acme.test", "auth", "TOKEN")]).unwrap();
        let portable = read(&db_a, &key_a).unwrap();

        let db_b = dir.join("B");
        write(&db_b, &key_b, &portable).unwrap();
        let got = read(&db_b, &key_b).unwrap();
        assert_eq!(got[0].value, "TOKEN");
    }
}
