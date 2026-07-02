//! Pack/unpack a profile's `user-data-dir` to portable bytes.
//!
//! `pack` tars+gzips the dir, EXCLUDING cache/crashpad/lock files, the machine-
//! bound `Local State` os_crypt key, and the encrypted `Cookies` DB; the cookies
//! are instead read, decrypted, and embedded as plaintext (`shardx-portable.json`).
//! `unpack` extracts everything and rebuilds the `Cookies` DB encrypted with the
//! DESTINATION machine's key — so a snapshot restores correctly across machines,
//! including Mac↔Windows where the on-disk key is not portable.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::cookies;
use crate::oscrypt::LocalCrypt;
use crate::portable::{PortableState, PORTABLE_FILE};

/// Relative-path prefixes excluded from snapshots (cache, transient state, and
/// machine-bound files we reconstruct on restore).
const EXCLUDE_PREFIXES: &[&str] = &[
    "Default/Cache",
    "Default/Code Cache",
    "Default/GPUCache",
    "Default/DawnCache",
    "Default/DawnGraphiteCache",
    "Default/DawnWebGPUCache",
    "Default/GrShaderCache",
    "Default/ShaderCache",
    "Default/Service Worker/CacheStorage",
    "Default/Service Worker/ScriptCache",
    "Default/Cookies",         // rebuilt from portable plaintext
    "Default/Network/Cookies", // rebuilt from portable plaintext
    // Saved passwords are encrypted with the machine-bound key and are NOT
    // ported in v1 (logins stay empty in PortableState); carrying the raw DB
    // across machines would leave an undecryptable file behind.
    "Default/Login Data",
    "Default/Login Data For Account",
    "GPUCache",
    "ShaderCache",
    "GrShaderCache",
    "Crashpad",
    "component_crx_cache",
    "extensions_crx_cache",
];

fn is_excluded(rel: &str) -> bool {
    if rel == "Local State" {
        return true; // machine-bound os_crypt key — destination mints its own
    }
    for p in EXCLUDE_PREFIXES {
        if rel == *p || rel.starts_with(&format!("{p}/")) {
            return true;
        }
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    if base.ends_with("-journal") {
        return true;
    }
    matches!(
        base,
        "LOCK"
            | "lockfile"
            | "SingletonLock"
            | "SingletonCookie"
            | "SingletonSocket"
            | "DevToolsActivePort"
            | ".DS_Store"
    )
}

/// Pack `udd` into compressed, portable snapshot bytes.
pub fn pack(udd: &Path) -> Result<Vec<u8>> {
    let crypt = LocalCrypt::open(udd)?;
    let cookies = cookies::read(&cookies::cookies_db_path(udd), &crypt).unwrap_or_default();
    let state = PortableState { cookies, logins: Vec::new() };
    let state_json = serde_json::to_vec(&state)?;

    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);

    // Embed the portable plaintext state first.
    let mut header = tar::Header::new_gnu();
    header.set_size(state_json.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, PORTABLE_FILE, &state_json[..])?;

    add_dir(&mut tar, udd, udd)?;
    let gz = tar.into_inner()?;
    Ok(gz.finish()?)
}

fn add_dir(tar: &mut tar::Builder<GzEncoder<Vec<u8>>>, root: &Path, dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded(&rel) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            add_dir(tar, root, &path)?;
        } else if meta.is_file() {
            let mut f = std::fs::File::open(&path)?;
            tar.append_file(&rel, &mut f)
                .with_context(|| format!("append {rel}"))?;
        }
        // symlinks are skipped intentionally
    }
    Ok(())
}

/// Extract a snapshot into `udd` and rebuild the Cookies DB with the local key.
/// Returns the embedded portable state.
///
/// Atomic: the snapshot is materialized in a sibling staging dir and only
/// swapped into place once fully built (extract + cookie rebuild). A failure
/// mid-way leaves the existing `udd` untouched; a crash leaves only a stale
/// staging dir that the next call cleans up. The swap also drops any local
/// files no longer present in the snapshot (state deleted on another machine),
/// which an in-place extract would have left behind.
pub fn unpack(bytes: &[u8], udd: &Path) -> Result<PortableState> {
    let staging = sibling(udd, "incoming")?;
    let backup = sibling(udd, "backup")?;

    // Crash recovery. If a prior run died between "move udd aside" and "move
    // staging into place", `.backup` holds the ONLY copy of the original udd —
    // restore it before touching anything. Only once udd exists is `.backup`
    // a safe-to-drop stale leftover.
    //
    // (Concurrency note: two unpacks of the same udd would race on these fixed
    // paths, but the caller serializes them — a profile is under one checkout
    // lock and the launcher refuses a second concurrent launch.)
    if !udd.exists() && backup.exists() {
        std::fs::rename(&backup, udd).context("recover interrupted snapshot swap")?;
    }
    remove_path(&staging);
    remove_path(&backup);
    std::fs::create_dir_all(&staging)?;

    // Build the new tree fully in staging; on any error, tear it down and
    // leave the live udd as-is.
    let state = match build_staging(bytes, udd, &staging) {
        Ok(s) => s,
        Err(e) => {
            remove_path(&staging);
            return Err(e);
        }
    };

    // Swap staging → udd. Move the old dir aside first so the rename lands on
    // a free path (rename-onto-existing fails on Windows); restore it if the
    // second rename fails so we never end up with no udd at all.
    let had_existing = udd.exists();
    if had_existing {
        std::fs::rename(udd, &backup).context("move current user-data-dir aside")?;
    }
    if let Err(e) = std::fs::rename(&staging, udd) {
        if had_existing {
            let _ = std::fs::rename(&backup, udd); // best-effort restore
        }
        remove_path(&staging);
        return Err(anyhow::Error::new(e).context("swap staged snapshot into place"));
    }
    remove_path(&backup);
    Ok(state)
}

/// Remove a path whether it's a dir, file, or symlink; ignore if absent.
fn remove_path(p: &Path) {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// Materialize a snapshot into `staging`, preserving `udd`'s machine-bound
/// `Local State` key so cookies re-encrypt to the same key this machine
/// already uses (matters on Windows, where the key lives in `Local State`;
/// on macOS/Linux the key is fixed and this is a harmless no-op).
fn build_staging(bytes: &[u8], udd: &Path, staging: &Path) -> Result<PortableState> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut state = PortableState::default();

    for entry in archive.entries()? {
        let mut e = entry?;
        let rel = e.path()?.to_string_lossy().replace('\\', "/");
        if rel == PORTABLE_FILE {
            let mut s = String::new();
            e.read_to_string(&mut s)?;
            state = serde_json::from_str(&s).unwrap_or_default();
            continue;
        }
        if is_excluded(&rel) {
            continue; // defensive; should already be absent
        }
        // Snapshots are member-uploadable bytes: only ever materialize plain
        // files and directories. A symlink/hardlink/device entry could plant a
        // link that escapes the udd on a later write — reject all of them.
        let et = e.header().entry_type();
        if !(et.is_file() || et.is_dir()) {
            continue;
        }
        let out = safe_join(staging, &rel)?;
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        e.unpack(&out)?;
    }

    // Carry over this machine's existing os_crypt key (if any) so we don't
    // orphan already-encrypted local data (e.g. Web Data autofill) behind a
    // freshly-minted key. Snapshots deliberately exclude Local State.
    let live_ls = udd.join("Local State");
    if live_ls.exists() {
        std::fs::copy(&live_ls, staging.join("Local State")).context("carry over Local State")?;
    }

    // Rebuild cookies encrypted with THIS machine's key.
    let crypt = LocalCrypt::open(staging)?;
    let db = cookies::cookies_db_path(staging);
    cookies::write(&db, &crypt, &state.cookies)?;
    Ok(state)
}

/// A sibling path of `udd` with a `.<suffix>` name, for staging/backup dirs.
fn sibling(udd: &Path, suffix: &str) -> Result<PathBuf> {
    let name = udd
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("user-data-dir has no final path component"))?;
    Ok(udd.with_file_name(format!("{name}.{suffix}")))
}

/// Join an archive-relative path under `root`, rejecting traversal.
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            bail!("unsafe path in archive: {rel}");
        }
        out.push(comp);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable::PortableCookie;

    #[test]
    fn pack_unpack_excludes_cache_and_keeps_cookies() {
        let base = std::env::temp_dir().join(format!("shardx-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("Default/Network")).unwrap();
        std::fs::create_dir_all(src.join("Default/Local Storage/leveldb")).unwrap();
        std::fs::create_dir_all(src.join("Default/Cache")).unwrap();

        // Keepable state + cache that must be dropped.
        std::fs::write(src.join("Default/Local Storage/leveldb/000003.log"), b"LSDATA").unwrap();
        std::fs::write(src.join("Default/Cache/data_0"), vec![0u8; 4096]).unwrap();
        std::fs::write(src.join("Default/Network/Cookies-journal"), b"junk").unwrap();

        // Encrypted cookies in the source DB.
        let scrypt = LocalCrypt::open(&src).unwrap();
        cookies::write(
            &src.join("Default/Network/Cookies"),
            &scrypt,
            &[PortableCookie {
                domain: ".example.com".into(),
                name: "sid".into(),
                value: "SECRET-VALUE".into(),
                path: "/".into(),
                expires: Some(4_102_444_800.0),
                secure: true,
                http_only: true,
                same_site: Some("Lax".into()),
            }],
        )
        .unwrap();

        let bytes = pack(&src).unwrap();
        let state = unpack(&bytes, &dst).unwrap();

        // Cache excluded, real state kept.
        assert!(!dst.join("Default/Cache/data_0").exists(), "cache must be excluded");
        assert!(!dst.join("Default/Network/Cookies-journal").exists(), "journal excluded");
        assert!(dst.join("Default/Local Storage/leveldb/000003.log").exists(), "state kept");
        assert!(!dst.join("Local State").exists(), "machine key not carried");

        // Portable state carried the cookie, and it's re-encrypted + readable in dst.
        assert_eq!(state.cookies.len(), 1);
        let dcrypt = LocalCrypt::open(&dst).unwrap();
        let got = cookies::read(&cookies::cookies_db_path(&dst), &dcrypt).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "SECRET-VALUE");
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(safe_join(Path::new("/tmp/x"), "../../etc/passwd").is_err());
        assert!(safe_join(Path::new("/tmp/x"), "Default/ok").is_ok());
    }

    #[test]
    fn unpack_swap_drops_stale_files_and_is_atomic() {
        let base = std::env::temp_dir().join(format!("shardx-snap-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("Default/Local Storage/leveldb")).unwrap();
        std::fs::write(src.join("Default/Local Storage/leveldb/000003.log"), b"NEW").unwrap();
        let scrypt = LocalCrypt::open(&src).unwrap();
        cookies::write(
            &src.join("Default/Network/Cookies"),
            &scrypt,
            &[PortableCookie {
                domain: ".example.com".into(),
                name: "sid".into(),
                value: "SWAP-VALUE".into(),
                path: "/".into(),
                expires: Some(4_102_444_800.0),
                secure: true,
                http_only: true,
                same_site: Some("Lax".into()),
            }],
        )
        .unwrap();
        let bytes = pack(&src).unwrap();

        // Pre-populate the destination with a stale file NOT in the snapshot.
        std::fs::create_dir_all(dst.join("Default")).unwrap();
        std::fs::write(dst.join("Default/stale.txt"), b"OLD").unwrap();

        unpack(&bytes, &dst).unwrap();

        // Stale file gone (full replacement), snapshot state present.
        assert!(!dst.join("Default/stale.txt").exists(), "stale file must be dropped");
        assert!(dst.join("Default/Local Storage/leveldb/000003.log").exists(), "new state present");
        // No staging/backup dirs linger.
        assert!(!base.join("dst.incoming").exists());
        assert!(!base.join("dst.backup").exists());

        let dcrypt = LocalCrypt::open(&dst).unwrap();
        let got = cookies::read(&cookies::cookies_db_path(&dst), &dcrypt).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "SWAP-VALUE");
    }

    #[test]
    fn unpack_recovers_udd_from_interrupted_swap() {
        // Simulate a crash between "move udd aside" and "move staging in":
        // udd is gone, `.backup` holds the only original. Even a FAILED unpack
        // must first restore the original from backup — never lose it.
        let base = std::env::temp_dir().join(format!("shardx-snap-recover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dst = base.join("dst");
        let backup = base.join("dst.backup");
        std::fs::create_dir_all(backup.join("Default")).unwrap();
        std::fs::write(backup.join("Default/orig.txt"), b"ORIGINAL").unwrap();

        let err = unpack(b"corrupt not gzip", &dst);
        assert!(err.is_err(), "corrupt snapshot still errors");
        // The original was recovered from backup, not lost.
        assert_eq!(std::fs::read(dst.join("Default/orig.txt")).unwrap(), b"ORIGINAL");
        assert!(!backup.exists(), "backup consumed by recovery");
    }

    #[cfg(unix)]
    #[test]
    fn unpack_rejects_symlink_entries() {
        use std::io::Write;
        // Hand-build a gzipped tar containing the portable file + a symlink.
        let mut state = Vec::new();
        write!(state, "{{\"cookies\":[],\"logins\":[]}}").unwrap();
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(state.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, PORTABLE_FILE, &state[..]).unwrap();
        // A symlink entry pointing outside the udd.
        let mut lh = tar::Header::new_gnu();
        lh.set_entry_type(tar::EntryType::Symlink);
        lh.set_size(0);
        lh.set_mode(0o777);
        lh.set_link_name("/etc/passwd").unwrap();
        lh.set_cksum();
        tar.append_data(&mut lh, "Default/evil", std::io::empty()).unwrap();
        let bytes = tar.into_inner().unwrap().finish().unwrap();

        let base = std::env::temp_dir().join(format!("shardx-snap-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dst = base.join("dst");
        unpack(&bytes, &dst).unwrap();
        // The symlink was skipped, not materialized.
        assert!(!dst.join("Default/evil").symlink_metadata().is_ok(), "symlink must be rejected");
    }

    #[test]
    fn unpack_failure_leaves_existing_udd_intact() {
        let base = std::env::temp_dir().join(format!("shardx-snap-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dst = base.join("dst");
        std::fs::create_dir_all(dst.join("Default")).unwrap();
        std::fs::write(dst.join("Default/keep.txt"), b"KEEP").unwrap();

        // Corrupt bytes → build_staging fails before any swap.
        let err = unpack(b"not a gzip stream", &dst);
        assert!(err.is_err(), "corrupt snapshot must error");
        // Existing udd untouched, no staging/backup left behind.
        assert_eq!(std::fs::read(dst.join("Default/keep.txt")).unwrap(), b"KEEP");
        assert!(!base.join("dst.incoming").exists());
        assert!(!base.join("dst.backup").exists());
    }
}
