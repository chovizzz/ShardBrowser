//! Cross-machine normalization of saved passwords in Chromium `Login Data`.
//!
//! Saved passwords use the same `os_crypt` v10 secret scheme as `Web Data`
//! (no SHA256(host) prefix — the `LocalCrypt::{encrypt,decrypt}_secret` form).
//! Like `Web Data`, the raw DB travels inside the snapshot and only the
//! encrypted `password_value` column is decrypted at pack time and re-sealed
//! with the destination key at unpack time. We deliberately do NOT rebuild the
//! schema: `logins` carries many version-varying columns (date_created,
//! times_used, form-field blobs, …) that Chromium owns.
//!
//! Rows are located by their stable SQLite `rowid`: the DB file travels
//! unchanged, so the rowids read at pack time still address the same rows at
//! unpack time — this needs no complex/version-varying composite key and
//! naturally handles multiple rows sharing a realm + username.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::oscrypt::LocalCrypt;
use crate::portable::PortableLogin;

pub fn login_data_path(udd: &Path) -> PathBuf {
    udd.join("Default").join("Login Data")
}

/// Read + decrypt saved passwords, keyed by `rowid`. Returns empty if the DB is
/// absent. Rows with no stored secret (empty blob — e.g. user-blacklisted
/// sites) are skipped. A non-empty blob that fails to decrypt aborts the read.
pub fn read(db_path: &Path, crypt: &LocalCrypt) -> Result<Vec<PortableLogin>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db_path.display()))?;
    let mut stmt = conn.prepare("SELECT rowid, password_value FROM logins")?;
    // Read the raw row, then decrypt OUTSIDE the rusqlite closure so a v10
    // decrypt failure can abort the read instead of being swallowed.
    let rows = stmt.query_map([], |r| {
        let rowid: i64 = r.get(0)?;
        let enc: Option<Vec<u8>> = r.get(1)?;
        Ok((rowid, enc))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (rowid, enc) = row?;
        let Some(enc) = enc.filter(|b| !b.is_empty()) else {
            continue; // no stored password for this row
        };
        // Fail closed: a non-empty v10 blob we can't decrypt must abort the
        // pack, never silently port an empty password that would overwrite the
        // real one when this row is re-encrypted on restore.
        let password_value = crypt.decrypt_secret(&enc).ok_or_else(|| {
            anyhow!("login row {rowid} failed v10 decryption — refusing to pack an empty password")
        })?;
        out.push(PortableLogin { rowid, password_value });
    }
    Ok(out)
}

/// Re-encrypt carried passwords with `crypt` and write them back into the DB in
/// place, one `UPDATE` per row keyed by `rowid`.
///
/// The carried `logins` slice and the DB's non-empty password rows must be a
/// **perfect bijection**: pack read (all-or-nothing) emits exactly one entry per
/// non-empty row, so a mismatch means a truncated, tampered, or otherwise
/// inconsistent snapshot. Rather than silently leave source-key ciphertext on a
/// row we didn't rewrite (undecryptable on this machine) or drop a password
/// whose row is gone, we verify — inside the write transaction — that:
///   * the DB is present whenever there are passwords to write,
///   * the carried rowids are duplicate-free, and
///   * they equal the set of the DB's non-empty `password_value` rows exactly,
/// and `bail!` on any violation. Returns the number of rows updated.
pub fn reencrypt_in_place(
    db_path: &Path,
    crypt: &LocalCrypt,
    logins: &[PortableLogin],
) -> Result<usize> {
    if !db_path.exists() {
        if logins.is_empty() {
            return Ok(0);
        }
        bail!(
            "snapshot carries {} saved password(s) but the Login Data DB is missing",
            logins.len()
        );
    }
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    let tx = conn.unchecked_transaction()?;

    // The exact set of rows a valid snapshot must account for: every row whose
    // password is source-key ciphertext (non-NULL, non-empty). Read inside the
    // tx so the check and the writes see one consistent view.
    let db_rowids: BTreeSet<i64> = {
        let mut stmt = tx.prepare(
            "SELECT rowid FROM logins WHERE password_value IS NOT NULL AND length(password_value) > 0",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut carried = BTreeSet::new();
    for l in logins {
        if !carried.insert(l.rowid) {
            bail!("snapshot repeats login rowid {} — refusing ambiguous re-encrypt", l.rowid);
        }
    }
    if carried != db_rowids {
        bail!(
            "snapshot logins don't match Login Data (carried {} rows, DB has {} encrypted) — \
             refusing to leave undecryptable passwords behind",
            carried.len(),
            db_rowids.len()
        );
    }

    let mut updated = 0usize;
    {
        let mut stmt = tx.prepare("UPDATE logins SET password_value = ?1 WHERE rowid = ?2")?;
        for l in logins {
            let enc = crypt.encrypt_secret(&l.password_value);
            let n = stmt.execute(rusqlite::params![enc, l.rowid])?;
            // Unreachable given the set-equality check above, but keep the guard:
            // a rowid in `db_rowids` addresses exactly one row.
            if n != 1 {
                bail!("login rowid {} matched {} rows on re-encrypt (expected exactly 1)", l.rowid, n);
            }
            updated += 1;
        }
    }
    tx.commit()?;
    // Fold our writes into the main DB file so the staged profile is
    // self-contained — no `-wal` left carrying frames the browser must replay
    // (no-op if the DB isn't in WAL mode). Best-effort: correctness already
    // holds via the committed transaction.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    Ok(updated)
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shardx-lg-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A `logins` table with just the columns our queries touch, plus a couple
    // of Chromium-shaped extras so it's a plain rowid table (not WITHOUT ROWID).
    fn create_logins(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, \
             password_value BLOB, signon_realm TEXT, blacklisted_by_user INTEGER);",
        )
        .unwrap();
    }
    fn insert(conn: &Connection, crypt: &LocalCrypt, realm: &str, user: &str, pw: &[u8]) {
        let enc = crypt.encrypt_secret(pw);
        conn.execute(
            "INSERT INTO logins (origin_url, username_value, password_value, signon_realm, blacklisted_by_user) \
             VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![realm, user, enc, realm],
        )
        .unwrap();
    }

    // Pack under key A, carry the same DB, re-seal under key B — the destination
    // key decrypts, the source key no longer does. Covers multiple rows sharing
    // a realm + username (distinct only by rowid).
    #[test]
    fn passwords_rekey_across_machines() {
        let dir = tmp("rk");
        let db = dir.join("Login Data");
        let src = LocalCrypt::with_key(vec![0x11; 16]);
        {
            let conn = Connection::open(&db).unwrap();
            create_logins(&conn);
            insert(&conn, &src, "https://site.test/", "alice", b"pw-one");
            insert(&conn, &src, "https://site.test/", "alice", b"pw-two"); // same realm+user
            insert(&conn, &src, "https://other.test/", "bob", b"\x00\xff binary");
        }

        let logins = read(&db, &src).unwrap();
        assert_eq!(logins.len(), 3);

        let dst = LocalCrypt::with_key(vec![0x22; 16]);
        assert_eq!(reencrypt_in_place(&db, &dst, &logins).unwrap(), 3);

        // Every row now decrypts under the destination key, source key fails.
        let conn = Connection::open(&db).unwrap();
        let mut stmt = conn.prepare("SELECT password_value FROM logins ORDER BY rowid").unwrap();
        let blobs: Vec<Vec<u8>> = stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(dst.decrypt_secret(&blobs[0]).unwrap(), b"pw-one");
        assert_eq!(dst.decrypt_secret(&blobs[1]).unwrap(), b"pw-two");
        assert_eq!(dst.decrypt_secret(&blobs[2]).unwrap(), b"\x00\xff binary");
        assert!(src.decrypt_secret(&blobs[0]).is_none());
    }

    // A blacklisted site (empty password blob) is skipped, not ported.
    #[test]
    fn blacklisted_rows_are_skipped() {
        let dir = tmp("bl");
        let db = dir.join("Login Data");
        let crypt = LocalCrypt::with_key(vec![0x33; 16]);
        let conn = Connection::open(&db).unwrap();
        create_logins(&conn);
        conn.execute(
            "INSERT INTO logins (origin_url, username_value, password_value, signon_realm, blacklisted_by_user) \
             VALUES ('https://nope.test/', '', X'', 'https://nope.test/', 1)",
            [],
        )
        .unwrap();
        insert(&conn, &crypt, "https://yes.test/", "carol", b"kept");
        drop(conn);

        let got = read(&db, &crypt).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].password_value, b"kept");
    }

    // A non-empty blob sealed with key A can't be read with key B — that must
    // error, not silently pack an empty password (which would wipe it).
    #[test]
    fn read_fails_on_undecryptable_password() {
        let dir = tmp("bad");
        let db = dir.join("Login Data");
        let key_a = LocalCrypt::with_key(vec![0xAA; 16]);
        let key_b = LocalCrypt::with_key(vec![0xBB; 16]);
        let conn = Connection::open(&db).unwrap();
        create_logins(&conn);
        insert(&conn, &key_a, "https://acme.test/", "auth", b"TOKEN");
        drop(conn);
        assert!(read(&db, &key_b).is_err(), "undecryptable password must error");
    }

    // The carried set must be a perfect bijection with the DB's non-empty
    // password rows. A mismatch (missing rowid, extra/omitted row, or a
    // duplicate) aborts BEFORE any write — the original row keeps its source key.
    #[test]
    fn reencrypt_rejects_set_mismatch_without_touching_rows() {
        let dir = tmp("miss");
        let db = dir.join("Login Data");
        let src = LocalCrypt::with_key(vec![0x44; 16]);
        let conn = Connection::open(&db).unwrap();
        create_logins(&conn);
        insert(&conn, &src, "https://site.test/", "alice", b"pw");
        drop(conn);
        let real_rowid = read(&db, &src).unwrap()[0].rowid;
        let dst = LocalCrypt::with_key(vec![0x45; 16]);

        // (a) a rowid the DB doesn't have.
        let phantom = PortableLogin { rowid: 999, password_value: b"x".to_vec() };
        assert!(reencrypt_in_place(&db, &dst, &[phantom]).is_err());
        // (b) empty carry while the DB still has an encrypted row.
        assert!(reencrypt_in_place(&db, &dst, &[]).is_err());
        // (c) a duplicate rowid.
        let dup = vec![
            PortableLogin { rowid: real_rowid, password_value: b"a".to_vec() },
            PortableLogin { rowid: real_rowid, password_value: b"b".to_vec() },
        ];
        assert!(reencrypt_in_place(&db, &dst, &dup).is_err());

        // After every rejected call the row is untouched: still the SOURCE key.
        assert_eq!(read(&db, &src).unwrap()[0].password_value, b"pw");
    }

    // A password committed only to the `-wal` (never checkpointed to the main
    // DB) must still be read at pack time and rekeyed at unpack time — the case
    // a hard-killed checkin leaves behind.
    #[test]
    fn passwords_in_uncheckpointed_wal_rekey() {
        let dir = tmp("wal");
        let db = dir.join("Login Data");
        let src = LocalCrypt::with_key(vec![0x66; 16]);

        // Writer in WAL mode with auto-checkpoint off; keep it open so the frame
        // is NOT checkpointed into the main DB before we read.
        let writer = Connection::open(&db).unwrap();
        writer.pragma_update(None, "journal_mode", "WAL").unwrap();
        writer.pragma_update(None, "wal_autocheckpoint", 0i64).unwrap();
        create_logins(&writer);
        insert(&writer, &src, "https://w.test/", "u", b"walpass");
        assert!(dir.join("Login Data-wal").exists(), "row should live in the WAL");

        // Pack-side read (READ_ONLY) sees the committed WAL frame.
        let carried = read(&db, &src).unwrap();
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].password_value, b"walpass");

        // Unpack-side rekey to a different key, then the destination key decrypts.
        let dst = LocalCrypt::with_key(vec![0x77; 16]);
        assert_eq!(reencrypt_in_place(&db, &dst, &carried).unwrap(), 1);
        drop(writer);
        assert_eq!(read(&db, &dst).unwrap()[0].password_value, b"walpass");
    }

    #[test]
    fn missing_db_is_noop_only_when_nothing_to_write() {
        let dir = tmp("empty");
        let crypt = LocalCrypt::with_key(vec![0x55; 16]);
        let missing = dir.join("Login Data");
        assert!(read(&missing, &crypt).unwrap().is_empty());
        assert_eq!(reencrypt_in_place(&missing, &crypt, &[]).unwrap(), 0);
        // But a missing DB with passwords to write is an error, not a silent drop.
        let orphan = PortableLogin { rowid: 1, password_value: b"x".to_vec() };
        assert!(reencrypt_in_place(&missing, &crypt, &[orphan]).is_err());
    }
}
