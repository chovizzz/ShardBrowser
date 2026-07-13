//! Shared ShardX logic used by the launcher (and, later, the Rust SDK):
//!
//! - [`oscrypt`] — Chromium `os_crypt` v10 cookie/secret encryption, with the
//!   key handled explicitly so encrypt/decrypt can be re-keyed across machines.
//! - [`cookies`] — read/write a profile's Chromium `Cookies` SQLite DB.
//! - [`snapshot`] — pack/unpack a `user-data-dir` to portable bytes, excluding
//!   cache and normalizing the (machine-bound) cookie encryption so a snapshot
//!   taken on one machine restores correctly on another (incl. Mac↔Windows).

pub mod cookies;
pub mod logins;
pub mod oscrypt;
pub mod portable;
pub mod snapshot;
pub mod webdata;

pub use oscrypt::LocalCrypt;
pub use portable::{PortableCookie, PortableLogin, PortableSecret, PortableState};
