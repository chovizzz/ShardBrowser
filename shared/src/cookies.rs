//! Read/write a profile's Chromium `Cookies` SQLite DB (schema v24).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
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
         is_secure, is_httponly, has_expires, samesite, top_frame_site_key, \
         source_scheme, source_port, has_cross_site_ancestor FROM cookies",
    )?;
    // Read the raw row (incl. `encrypted_value` + plaintext fallback), then
    // decrypt OUTSIDE the rusqlite closure so a v10 decrypt failure can abort the
    // read instead of silently packing an empty cookie value.
    let rows = stmt.query_map([], |r| {
        let plain: String = r.get(2)?;
        let enc: Vec<u8> = r.get(3)?;
        let has_expires: i64 = r.get(8)?;
        let cookie = PortableCookie {
            value: String::new(), // filled below
            domain: r.get(0)?,
            name: r.get(1)?,
            path: r.get(4)?,
            expires: if has_expires != 0 {
                Some(chromium_to_unix_secs(r.get(5)?))
            } else {
                None
            },
            secure: r.get::<_, i64>(6)? != 0,
            http_only: r.get::<_, i64>(7)? != 0,
            same_site: Some(samesite_to_str(r.get(9)?).to_string()),
            // Preserve the unique-index components so partitioned cookies restore
            // to the exact same scope rather than collapsing together.
            top_frame_site_key: r.get(10)?,
            source_scheme: Some(r.get(11)?),
            source_port: Some(r.get(12)?),
            has_cross_site_ancestor: Some(r.get(13)?),
        };
        Ok((enc, plain, cookie))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (enc, plain, mut cookie) = row?;
        cookie.value = crypt.try_decrypt_cookie(&enc, &plain, &cookie.domain).ok_or_else(|| {
            anyhow!(
                "cookie {}={} failed v10 decryption — refusing to pack an empty value",
                cookie.domain,
                cookie.name
            )
        })?;
        out.push(cookie);
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
             VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, ?14, ?15, ?16, 0, ?17)",
        )?;
        for c in cookies {
            let enc = crypt.encrypt_cookie(&c.domain, &c.value);
            let has_expires = c.expires.is_some();
            let expires_utc = c.expires.map(unix_to_chromium).unwrap_or(0);
            // Preserve the source/partition unique-index components; legacy
            // snapshots lack them, so fall back to the old derived defaults.
            let source_scheme = c.source_scheme.unwrap_or(if c.secure { 2 } else { 1 });
            let source_port = c.source_port.unwrap_or(if c.secure { 443 } else { 80 });
            let has_cross_site_ancestor = c.has_cross_site_ancestor.unwrap_or(1);
            stmt.execute(params![
                now,
                c.domain,
                c.top_frame_site_key,
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
                has_cross_site_ancestor,
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
            ..Default::default()
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

    #[test]
    fn partitioned_cookies_keep_distinct_scope() {
        let dir = std::env::temp_dir().join(format!("shardx-ckpart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("Cookies");
        let crypt = LocalCrypt::open(&dir).unwrap();

        // Same host/name/path, but one is CHIPS-partitioned to a top-level site.
        let unpart = sample(".example.com", "sid", "unpartitioned");
        let mut part = sample(".example.com", "sid", "partitioned-to-shop");
        part.top_frame_site_key = "https://shop.example".into();

        write(&db, &crypt, &[unpart, part]).unwrap();
        let got = read(&db, &crypt).unwrap();

        // Before the fix these collapsed to one row (top_frame_site_key forced to
        // '') — now both survive with their partition preserved.
        assert_eq!(got.len(), 2, "distinct partitions must not collide");
        let u = got.iter().find(|c| c.top_frame_site_key.is_empty()).unwrap();
        let p = got.iter().find(|c| !c.top_frame_site_key.is_empty()).unwrap();
        assert_eq!(u.value, "unpartitioned");
        assert_eq!(p.value, "partitioned-to-shop");
        assert_eq!(p.top_frame_site_key, "https://shop.example");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn read_fails_on_undecryptable_v10_cookie() {
        // A v10 cookie sealed with key A can't be read with key B — that must
        // error, not silently pack an empty value (which would wipe the cookie).
        let dir = std::env::temp_dir().join(format!("shardx-ckbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("Cookies");
        let key_a = LocalCrypt::with_key(vec![0xAA; 16]);
        let key_b = LocalCrypt::with_key(vec![0xBB; 16]);
        write(&db, &key_a, &[sample(".acme.test", "auth", "TOKEN")]).unwrap();
        assert!(read(&db, &key_b).is_err(), "undecryptable v10 cookie must error");
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
