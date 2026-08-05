use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::models::User;
use crate::{auth, util};

/// Open (creating if needed) the SQLite DB and run migrations.
pub async fn init_pool(cfg: &Config) -> anyhow::Result<SqlitePool> {
    tokio::fs::create_dir_all(&cfg.data_dir).await?;
    tokio::fs::create_dir_all(&cfg.blob_dir).await?;

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db_path))?
        .create_if_missing(true)
        .foreign_keys(true)
        // Writers queue instead of failing fast when a checkin transaction
        // briefly holds the write lock.
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    // `journal_mode` is a persistent property of the database FILE, so reading it
    // through any pooled connection reports the whole DB's state. sqlx no longer
    // sends a journal_mode pragma by default, which means a freshly created DB
    // runs on SQLite's rollback journal, where a reader and a writer block each
    // other. (WAL is the one mode that sticks to the file; the rollback modes are
    // per-connection defaults, which is why only WAL can be observed here as a
    // property of the DB rather than of our own connect options.) We only observe
    // and warn: switching into WAL needs exclusive access, which `busy_timeout` is
    // no substitute for, so it belongs in a planned downtime window and not in a
    // server about to start serving. Failing to read either pragma is fatal —
    // running migrations against a database we can't even interrogate isn't worth
    // the risk.
    let journal_mode: String = sqlx::query_scalar("PRAGMA main.journal_mode")
        .fetch_one(&pool)
        .await?;
    let sqlite_version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&pool)
        .await?;
    let is_wal = journal_mode.trim().eq_ignore_ascii_case("wal");
    let wal_safe = has_wal_reset_fix(&sqlite_version);
    // Always state both, so the healthy case is still auditable from the log
    // (the README points operators here to identify the linked SQLite).
    tracing::info!("SQLite {sqlite_version}, journal_mode '{journal_mode}' ({})", cfg.db_path);
    if is_wal && !wal_safe {
        // The dangerous combination, and the reason the version is logged at all:
        // this SQLite predates the WAL-reset fix, and we open several connections
        // that write and checkpoint concurrently — exactly the pattern that can
        // corrupt a WAL database. Louder than the "not WAL" case below.
        tracing::warn!(
            "SQLite {} is running {} in WAL mode but predates the WAL-reset corruption fix \
             (3.51.3, backported to 3.50.7 / 3.44.6). This server opens up to 8 connections, \
             which is the affected concurrent write/checkpoint pattern. Upgrade the SQLite \
             this binary links against, or stop every user of the database and move it back \
             off WAL with a version-checked SQLite tool. Upstream rates the bug as very \
             rare (they could not reproduce it without injected test logic), so plan this \
             properly rather than as an emergency. See \"Database journal mode (WAL)\" \
             in server/README.md.",
            sqlite_version,
            cfg.db_path
        );
    } else if !is_wal {
        tracing::warn!(
            // Deliberately phrased for any non-WAL mode: `delete`/`truncate`/`persist`
            // are rollback journals, but `off` has no journal at all (and no crash
            // recovery — called out separately below).
            "SQLite journal_mode is '{}' (not WAL) for {} — WAL's reader/writer concurrency \
             is unavailable in this mode, so a reader and a writer serialize against each \
             other (WAL would not lift the single-writer limit either).{} The server does \
             NOT change this automatically: unlike the rollback modes, WAL is a persistent \
             property of the database file, and switching into it needs exclusive access. \
             Running SQLite {}. See \"Database \
             journal mode (WAL)\" in server/README.md for the offline procedure — including \
             the SQLite version prerequisite, which this runtime does{} satisfy.",
            journal_mode,
            cfg.db_path,
            if journal_mode.trim().eq_ignore_ascii_case("off") {
                " journal_mode=off ALSO disables rollback entirely: a crash mid-transaction \
                 can leave the database corrupt and unrecoverable."
            } else {
                ""
            },
            sqlite_version,
            if wal_safe { "" } else { " NOT" }
        );
    }

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Does this SQLite carry the fix for the WAL-reset concurrency bug that can
/// corrupt a WAL database when several connections write/checkpoint at once?
///
/// Fixed in 3.51.3, backported to the 3.50.x and 3.44.x branches (3.50.7 /
/// 3.44.6). Anything older on those branches — or any other branch at or below
/// 3.51.2 — must not be considered safe for WAL. (Pre-3.7.0 lands here too;
/// WAL did not exist before 3.7.0, so it is unaffected rather than vulnerable,
/// but it is equally not something to enable WAL on.) An unparseable version is
/// treated as unsafe: we'd rather warn about a runtime we can't identify than
/// stay quiet about it.
fn has_wal_reset_fix(version: &str) -> bool {
    let mut parts = version.trim().split('.').map(|p| {
        p.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").parse::<u32>()
    });
    let (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    match (major, minor) {
        (3, 51) => patch >= 3,
        (3, 50) => patch >= 7,
        (3, 44) => patch >= 6,
        // Any branch newer than 3.51 carries the fix; everything older than the
        // three patched branches (and the unpatched tails of 3.45..=3.49) does not.
        (3, m) => m > 51,
        (m, _) => m > 3,
    }
}

/// On an empty DB, create the initial admin from config.
pub async fn bootstrap_admin(pool: &SqlitePool, cfg: &Config) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    // On a network-facing bind, a weak/default admin password is remote-takeover
    // by default. Loopback only exposes it locally (a warning suffices) and an
    // explicit opt-out covers exposed-dev setups.
    let guard_exposed = !cfg.bind_is_loopback()
        && !std::env::var("SHARDX_ALLOW_INSECURE_ADMIN").is_ok_and(|v| v == "1");

    if count == 0 {
        // Creating the first admin: we have the plaintext, so reject empty /
        // too-short / placeholder passwords up front.
        if guard_exposed && is_weak_password(&cfg.admin_pass) {
            anyhow::bail!(
                "refusing to bootstrap the admin account with a weak/default password on a \
                 non-loopback bind ({}). Set SHARDX_ADMIN_PASS to a strong secret \
                 (recommended), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to \
                 override.",
                cfg.bind
            );
        }
        let hash = auth::hash_password(&cfg.admin_pass).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        sqlx::query(
            "INSERT INTO users (id, username, pw_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
        )
        .bind(util::new_id())
        .bind(&cfg.admin_user)
        .bind(hash)
        .bind(util::now_rfc3339())
        .execute(pool)
        .await?;
        tracing::warn!(
            "bootstrapped admin user '{}' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, \
             then change the password",
            cfg.admin_user
        );
    }

    // Also catch an already-seeded weak admin (e.g. a DB first bootstrapped with
    // admin/admin, or set up on loopback then later exposed). Only placeholder
    // passwords are testable from a stored hash — length-only-weak ones set on an
    // existing install aren't caught here, nor are case variants of a placeholder
    // (the hash pins the exact bytes; we only test the canonical spellings); the
    // bootstrap check above covers new installs case-insensitively. An admin whose
    // password was changed to a strong one passes.
    if guard_exposed {
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT pw_hash FROM users WHERE role = 'admin'")
                .fetch_all(pool)
                .await?;
        let weak = hashes
            .iter()
            .any(|h| WEAK_PASSWORDS.iter().any(|w| auth::verify_password(w, h).is_ok()));
        if weak {
            anyhow::bail!(
                "an admin account still uses a weak/default password while binding a \
                 non-loopback address ({}). Change it (POST /me/password or an admin \
                 reset), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to override.",
                cfg.bind
            );
        }
    }
    Ok(())
}

/// Well-known placeholder passwords we refuse to expose. Also used to detect an
/// already-bootstrapped weak admin from its stored hash.
const WEAK_PASSWORDS: &[&str] = &[
    "admin",
    "admin123",
    "password",
    "password123",
    "secret",
    "change-me",
    "changeme",
    "changeme123",
    "changethis",
    "root",
    "test",
    "letmein",
    "qwerty",
    "123456",
];

/// A password too weak to expose on a public bind: empty, too short, or a known
/// placeholder.
fn is_weak_password(pw: &str) -> bool {
    pw.len() < 8 || WEAK_PASSWORDS.iter().any(|w| pw.eq_ignore_ascii_case(w))
}

pub async fn find_user(pool: &SqlitePool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_user_by_name(pool: &SqlitePool, name: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_reset_fix_detection() {
        // Patched: the fix release and both backport branches, plus anything newer.
        for ok in ["3.51.3", "3.51.4", "3.52.0", "3.50.7", "3.50.9", "3.44.6", "4.0.0"] {
            assert!(has_wal_reset_fix(ok), "{ok} should be considered patched");
        }
        // Affected: pre-fix tails of the patched branches, unpatched branches in
        // between, the version currently bundled, and anything we can't parse.
        for bad in ["3.51.2", "3.50.6", "3.44.5", "3.46.0", "3.49.9", "3.7.0", "", "unknown"] {
            assert!(!has_wal_reset_fix(bad), "{bad} should be considered affected");
        }
    }

    #[test]
    fn weak_password_detection() {
        // Placeholders (case-insensitive) and too-short/empty are weak.
        for w in ["admin", "ADMIN", "secret", "change-me", "changethis", "123456", "", "short7"] {
            assert!(is_weak_password(w), "{w:?} should be weak");
        }
        // A long, non-placeholder secret is fine.
        for ok in ["a-strong-unique-pass", "Xk9$2mQ!vz7Lp", "correct horse battery staple"] {
            assert!(!is_weak_password(ok), "{ok:?} should be accepted");
        }
    }

    fn cfg(bind: &str) -> Config {
        Config {
            bind: bind.into(),
            data_dir: String::new(),
            db_path: String::new(),
            blob_dir: String::new(),
            token_secret: "t".into(),
            token_ttl_secs: 3600,
            admin_user: "admin".into(),
            admin_pass: "unused-here".into(),
            lease_ttl_secs: 90,
            snapshot_keep: 5,
            max_snapshot_bytes: 1024,
            trust_proxy: false,
        }
    }

    async fn mem_pool() -> SqlitePool {
        // max_connections(1) so every query hits the same in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    async fn seed_admin(pool: &SqlitePool, password: &str) {
        let hash = auth::hash_password(password).unwrap();
        sqlx::query("INSERT INTO users (id, username, pw_hash, role, created_at) VALUES ('a1','admin',?,'admin','2020-01-01T00:00:00+00:00')")
            .bind(hash)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn exposed_bind_rejects_existing_weak_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "admin").await; // the classic default
        // Network-facing bind + an admin still on a default password → refuse.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_err());
        // Same DB on a loopback bind is tolerated (local-only exposure).
        assert!(bootstrap_admin(&pool, &cfg("127.0.0.1:8080")).await.is_ok());
    }

    #[tokio::test]
    async fn exposed_bind_accepts_strong_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "a-strong-unique-password").await;
        // A changed-to-strong admin passes even on an exposed bind.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_ok());
    }
}
