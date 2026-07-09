// Persistent storage layout under the user's config dir:
//   $CONFIG/shardx-launcher/
//     profiles/                   ← fingerprint profile JSON files
//     proxies.json                ← saved proxy list
//     user-data/<profile-id>/     ← per-profile user-data-dir for ShardX
//     settings.json               ← global app settings

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn config_root() -> Result<PathBuf> {
    let base = dirs::config_dir().context("OS config dir unavailable")?;
    let root = base.join("shardx-launcher");
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

pub fn profiles_dir() -> Result<PathBuf> {
    let p = config_root()?.join("profiles");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

pub fn fingerprints_dir() -> Result<PathBuf> {
    let p = config_root()?.join("fingerprints");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Cached Widevine CDM, seeded from a host Chrome install (or
/// downloaded from the project's git LFS bucket for end users).  When
/// present, every freshly-created profile's user-data-dir gets a
/// pre-warmed `WidevineCdm/` copy so the browser doesn't sit waiting
/// on the component updater the first time a DRM page (Netflix /
/// Spotify / etc.) loads.
pub fn widevine_cache_dir() -> Result<PathBuf> {
    Ok(config_root()?.join("widevine-cdm"))
}

pub fn user_data_root() -> Result<PathBuf> {
    let p = config_root()?.join("user-data");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

pub fn proxies_path() -> Result<PathBuf> {
    Ok(config_root()?.join("proxies.json"))
}

pub fn settings_path() -> Result<PathBuf> {
    Ok(config_root()?.join("settings.json"))
}

/// Write a file that holds credentials/secrets (server token, per-profile
/// lock_token, proxy passwords) with owner-only permissions (0600 on Unix), so
/// it isn't exposed on a shared machine or via a world-readable backup. On
/// Windows the per-user profile ACL already restricts it. New files are created
/// 0600 up front (no world-readable window); an existing file is fixed too.
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let contents = contents.as_ref();
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Write a sibling temp at 0600, fsync, then atomically rename it over the
        // target. Rename replaces the inode, so a reader sees the whole old or
        // whole new file (never a partial write), an FD held on the old inode
        // can't observe the new secret, and the new content is never briefly
        // world-readable.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("cred"),
            uuid::Uuid::new_v4().simple()
        ));
        let write_tmp = || -> Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            // Force exact 0600 (mode(0o600) alone is still filtered by umask).
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(contents)?;
            f.sync_all()?;
            Ok(())
        };
        if let Err(e) = write_tmp().and_then(|()| Ok(std::fs::rename(&tmp, path)?)) {
            let _ = std::fs::remove_file(&tmp); // don't leave a stray temp behind
            return Err(e);
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// ProxyShard billing-API config (Bearer key). Kept in its own file so the
/// Settings page (which round-trips the whole Settings struct) can never
/// clobber the saved key.
pub fn psapi_path() -> Result<PathBuf> {
    Ok(config_root()?.join("psapi.json"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_private_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("shardx-priv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.json");
        // Pre-create world-readable to prove an existing file is tightened too.
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, br#"{"token":"x"}"#).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential file must be owner-only");
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"token":"x"}"#);
    }
}
