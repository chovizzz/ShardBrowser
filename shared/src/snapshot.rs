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
pub fn unpack(bytes: &[u8], udd: &Path) -> Result<PortableState> {
    std::fs::create_dir_all(udd)?;
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
        let out = safe_join(udd, &rel)?;
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        e.unpack(&out)?;
    }

    // Rebuild cookies encrypted with THIS machine's key.
    let crypt = LocalCrypt::open(udd)?;
    let db = cookies::cookies_db_path(udd);
    cookies::write(&db, &crypt, &state.cookies)?;
    Ok(state)
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
}
