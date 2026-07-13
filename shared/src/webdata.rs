//! Cross-machine normalization of Chromium `Web Data` os_crypt secrets.
//!
//! `Web Data` (autofill + payment info) travels inside a snapshot as the real
//! SQLite file, but its encrypted columns (credit-card numbers, CVCs, IBANs)
//! are sealed with the SOURCE machine's os_crypt key (v10, no host prefix — the
//! `LocalCrypt::{encrypt,decrypt}_secret` scheme). Left untouched they'd be
//! undecryptable on the destination. So — like cookies — we decrypt them into
//! portable plaintext at pack time and re-encrypt them with the destination key
//! at unpack time.
//!
//! Unlike cookies we do NOT rebuild the DB from scratch: `Web Data` carries many
//! version-varying tables (autofill, addresses, keywords, token_service, …), so
//! we keep the real DB and only rewrite the known encrypted columns, keyed by
//! each row's stable `guid`. Any table/column a given engine version lacks is
//! skipped, and any row we can't decrypt is left as-is (best-effort residue).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::oscrypt::LocalCrypt;
use crate::portable::PortableSecret;

/// Local os_crypt-secret-encrypted columns to normalize: `(table, key_col,
/// enc_col)`. Every identifier here is a compile-time constant — they are the
/// ONLY table/column names ever interpolated into SQL, so a snapshot can't
/// steer a write at an arbitrary table (a `PortableSecret.table` from the blob
/// is only ever *matched against* this list, never trusted directly).
///
/// Scope is deliberately **local, `guid`-keyed** payment/autofill data. Account-
/// or server-bound secrets (`unmasked_credit_cards`, `server_stored_cvc`,
/// `token_service.encrypted_token`) are intentionally left out: they re-sync
/// from the signed-in Google account on the destination, so normalizing them
/// here would be pointless (and, for tokens, account-identity-bound). A column
/// a given Chromium version doesn't have is skipped via [`column_exists`], so
/// this list may over-approximate a specific engine without harm.
const ENCRYPTED_FIELDS: &[(&str, &str, &str)] = &[
    ("credit_cards", "guid", "card_number_encrypted"),
    ("local_stored_cvc", "guid", "value_encrypted"),
    ("local_ibans", "guid", "value_encrypted"),
];

pub fn web_data_path(udd: &Path) -> PathBuf {
    udd.join("Default").join("Web Data")
}

/// True if `table`.`col` exists in this DB. Tolerates schema drift across
/// engine versions: a missing table yields zero rows, not an error.
fn column_exists(conn: &Connection, table: &str, col: &str) -> bool {
    let Ok(mut stmt) = conn.prepare(&format!("PRAGMA table_info(\"{table}\")")) else {
        return false;
    };
    // PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk.
    let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(1)) else {
        return false;
    };
    let found = rows.flatten().any(|c| c == col);
    found
}

/// Read + decrypt every known `Web Data` secret. Returns empty if the DB is
/// absent. Rows that don't decrypt (or are empty) are skipped.
pub fn read(db_path: &Path, crypt: &LocalCrypt) -> Result<Vec<PortableSecret>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db_path.display()))?;
    let mut out = Vec::new();
    for (table, key_col, enc_col) in ENCRYPTED_FIELDS {
        if !column_exists(&conn, table, key_col) || !column_exists(&conn, table, enc_col) {
            continue;
        }
        let sql = format!("SELECT \"{key_col}\", \"{enc_col}\" FROM \"{table}\"");
        let mut stmt = conn.prepare(&sql)?;
        // Read the blob as nullable: a row with a NULL/absent secret must skip,
        // not abort the whole table. `.flatten()` likewise drops any row that
        // fails to decode rather than losing every secret in this DB.
        let rows = stmt.query_map([], |r| {
            let key: String = r.get(0)?;
            let enc: Option<Vec<u8>> = r.get(1)?;
            Ok((key, enc))
        })?;
        for (key, enc) in rows.flatten() {
            let Some(enc) = enc.filter(|b| !b.is_empty()) else {
                continue; // no stored secret for this row
            };
            if let Some(value) = crypt.decrypt_secret(&enc) {
                out.push(PortableSecret { table: (*table).to_string(), key, value });
            }
        }
    }
    Ok(out)
}

/// Re-encrypt carried secrets with `crypt` and write them back into the DB in
/// place, one `UPDATE` per row keyed by `guid`. No-op if the DB is absent or
/// there's nothing to write. Only columns from [`ENCRYPTED_FIELDS`] are ever
/// touched; a secret naming an unknown table (or one the destination engine
/// lacks) is ignored. Returns the number of rows updated.
pub fn reencrypt_in_place(
    db_path: &Path,
    crypt: &LocalCrypt,
    secrets: &[PortableSecret],
) -> Result<usize> {
    if secrets.is_empty() || !db_path.exists() {
        return Ok(0);
    }
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    let tx = conn.unchecked_transaction()?;
    let mut updated = 0usize;
    for s in secrets {
        // Resolve the columns from the hardcoded map by table name — never from
        // the (untrusted) snapshot blob.
        let Some(&(_, key_col, enc_col)) =
            ENCRYPTED_FIELDS.iter().find(|(t, _, _)| *t == s.table.as_str())
        else {
            continue;
        };
        if !column_exists(&tx, &s.table, key_col) || !column_exists(&tx, &s.table, enc_col) {
            continue;
        }
        let sql = format!("UPDATE \"{}\" SET \"{enc_col}\" = ?1 WHERE \"{key_col}\" = ?2", s.table);
        let enc = crypt.encrypt_secret(&s.value);
        updated += tx.execute(&sql, rusqlite::params![enc, s.key])?;
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

    #[test]
    fn card_number_rekeys_across_machines() {
        let dir = std::env::temp_dir().join(format!("shardx-wd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("Web Data");

        // Source machine: a saved card sealed with key A.
        let src = LocalCrypt::with_key(vec![0x11; 16]);
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE credit_cards (guid TEXT PRIMARY KEY, name_on_card TEXT, \
                 card_number_encrypted BLOB);",
            )
            .unwrap();
            let enc = src.encrypt_secret(b"4111111111111111");
            conn.execute(
                "INSERT INTO credit_cards VALUES (?1, ?2, ?3)",
                rusqlite::params!["card-guid-1", "Ada Lovelace", enc],
            )
            .unwrap();
        }

        // Pack: decrypt with source key.
        let secrets = read(&db, &src).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].table, "credit_cards");
        assert_eq!(secrets[0].key, "card-guid-1");
        assert_eq!(secrets[0].value, b"4111111111111111");

        // Restore: re-seal with a DIFFERENT destination key, in place.
        let dst = LocalCrypt::with_key(vec![0x22; 16]);
        let n = reencrypt_in_place(&db, &dst, &secrets).unwrap();
        assert_eq!(n, 1);

        // The destination key now decrypts the (rewritten) blob; the old key
        // no longer does. Row metadata (name) is untouched.
        let conn = Connection::open(&db).unwrap();
        let (name, blob): (String, Vec<u8>) = conn
            .query_row(
                "SELECT name_on_card, card_number_encrypted FROM credit_cards WHERE guid = 'card-guid-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(name, "Ada Lovelace");
        assert_eq!(dst.decrypt_secret(&blob).unwrap(), b"4111111111111111");
        assert!(src.decrypt_secret(&blob).is_none() || src.decrypt_secret(&blob).unwrap() != b"4111111111111111");
    }

    #[test]
    fn missing_db_and_absent_tables_are_noops() {
        let dir = std::env::temp_dir().join(format!("shardx-wd-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let crypt = LocalCrypt::with_key(vec![0x33; 16]);

        // Absent DB.
        let missing = dir.join("Web Data");
        assert!(read(&missing, &crypt).unwrap().is_empty());
        assert_eq!(reencrypt_in_place(&missing, &crypt, &[]).unwrap(), 0);

        // DB present but without any of the encrypted tables.
        let conn = Connection::open(&missing).unwrap();
        conn.execute_batch("CREATE TABLE autofill (name TEXT, value TEXT);").unwrap();
        drop(conn);
        assert!(read(&missing, &crypt).unwrap().is_empty());
    }
}
