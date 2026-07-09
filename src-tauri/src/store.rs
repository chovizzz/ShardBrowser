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
        // New files are created 0600. For an EXISTING file we do NOT truncate in
        // the open — instead we tighten the mode on the fd FIRST, then truncate
        // and write, so the new secret is never held in a world-readable file
        // (and chmod goes through the fd, avoiding a path-based race).
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.set_len(0)?;
        let mut f = f;
        f.write_all(contents)?;
        f.flush()?;
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
