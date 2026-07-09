//! Cookie import/export for ShardX profiles.
//!
//! This delegates entirely to `shardx-core` (the same cookie + os_crypt code the
//! team-server snapshot path uses) so the CHIPS partition keys and host-bound
//! decryption stay correct here too — instead of maintaining a second, drifting
//! copy of the scheme. The UI/API cookie type is `shardx_core::PortableCookie`.

use anyhow::Result;
use shardx_core::cookies::{cookies_db_path, read, write};
use shardx_core::LocalCrypt;

use crate::profile;

/// Tool-friendly cookie shape (re-exported): the 8 common fields with
/// `httpOnly` / `sameSite` camelCase aliases, plus the CHIPS partition + source
/// unique-key components — all serde-defaulted, so older JSON still imports.
pub use shardx_core::PortableCookie as Cookie;

/// Export a profile's decrypted cookies. Empty if the profile has no Cookies DB.
pub fn export(profile_id: &str) -> Result<Vec<Cookie>> {
    let udd = profile::user_data_dir(profile_id)?;
    let db = cookies_db_path(&udd);
    // Bail before opening the key: a read-only export of a never-launched
    // profile must not mint a `Local State` os_crypt key (a Windows write).
    if !db.exists() {
        return Ok(Vec::new());
    }
    let crypt = LocalCrypt::open(&udd)?;
    read(&db, &crypt)
}

/// Import cookies, re-encrypted with this profile's key (partition keys
/// preserved). Caller MUST stop the profile first.
pub fn import(profile_id: &str, cookies: &[Cookie]) -> Result<usize> {
    let udd = profile::user_data_dir(profile_id)?;
    let crypt = LocalCrypt::open(&udd)?;
    write(&cookies_db_path(&udd), &crypt, cookies)
}
