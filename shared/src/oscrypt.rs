//! Chromium `os_crypt` v10 encryption, with the key handled explicitly.
//!
//! A v10 blob is `b"v10"` followed by a per-OS cipher body:
//!   - macOS/Linux: AES-128-CBC (fixed IV), key = PBKDF2-HMAC-SHA1 of a fixed
//!     password (ShardX runs with `--use-mock-keychain`, so the key is stable).
//!   - Windows: AES-256-GCM (`nonce||ct||tag`), key = DPAPI-unwrapped
//!     `os_crypt.encrypted_key` from the profile's `Local State`.
//!
//! Cookie values carry a 32-byte `SHA256(host)` prefix (Chromium ≥130); saved
//! secrets (passwords) do not. The same key both encrypts and decrypts on a
//! given machine — snapshots move *plaintext* across machines and re-encrypt
//! with the destination key, so cross-machine (incl. Mac↔Windows) works.

use std::path::Path;

use anyhow::Result;
use sha2::{Digest, Sha256};

/// A resolved local os_crypt key plus the per-OS cipher.
#[derive(Clone)]
pub struct LocalCrypt {
    key: Vec<u8>,
}

impl LocalCrypt {
    /// Resolve the machine's key for the given user-data-dir.
    pub fn open(udd: &Path) -> Result<Self> {
        Ok(Self {
            key: local_key(udd)?,
        })
    }

    /// Construct with an explicit key (cross-machine re-keying, tests).
    pub fn with_key(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Encrypt a cookie value (adds the v10 frame + SHA256(host) prefix).
    pub fn encrypt_cookie(&self, host: &str, value: &str) -> Vec<u8> {
        let mut plaintext = Sha256::digest(host.as_bytes()).to_vec();
        plaintext.extend_from_slice(value.as_bytes());
        frame_v10(cipher::encrypt(&self.key, &plaintext))
    }

    /// Decrypt a cookie's `encrypted_value`; legacy rows fall back to `plain`.
    pub fn decrypt_cookie(&self, encrypted: &[u8], plain: &str) -> String {
        match unframe_v10(encrypted) {
            None => plain.to_string(),
            Some(body) => match cipher::decrypt(&self.key, body) {
                Some(pt) => String::from_utf8_lossy(&strip_host_prefix(pt)).into_owned(),
                None => String::new(),
            },
        }
    }

    /// Encrypt an arbitrary secret (saved password) — v10 frame, no host prefix.
    pub fn encrypt_secret(&self, value: &[u8]) -> Vec<u8> {
        frame_v10(cipher::encrypt(&self.key, value))
    }

    /// Decrypt a v10 secret blob; `None` if it isn't v10 or fails to decrypt.
    pub fn decrypt_secret(&self, encrypted: &[u8]) -> Option<Vec<u8>> {
        cipher::decrypt(&self.key, unframe_v10(encrypted)?)
    }
}

fn frame_v10(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + body.len());
    out.extend_from_slice(b"v10");
    out.extend_from_slice(&body);
    out
}

fn unframe_v10(blob: &[u8]) -> Option<&[u8]> {
    if blob.len() >= 3 && &blob[..3] == b"v10" {
        Some(&blob[3..])
    } else {
        None
    }
}

fn strip_host_prefix(mut pt: Vec<u8>) -> Vec<u8> {
    if pt.len() >= 32 {
        pt.drain(0..32);
    }
    pt
}

// ---- per-OS key derivation ----

#[cfg(target_os = "macos")]
fn local_key(_udd: &Path) -> Result<Vec<u8>> {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"mock_password", b"saltysalt", 1003, &mut key);
    Ok(key.to_vec())
}

#[cfg(target_os = "linux")]
fn local_key(_udd: &Path) -> Result<Vec<u8>> {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"peanuts", b"saltysalt", 1, &mut key);
    Ok(key.to_vec())
}

#[cfg(target_os = "windows")]
fn local_key(udd: &Path) -> Result<Vec<u8>> {
    cipher::os_crypt_key(udd)
}

// ---- POSIX cipher: AES-128-CBC, fixed IV ----

#[cfg(not(target_os = "windows"))]
mod cipher {
    use aes::Aes128;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

    type Enc = cbc::Encryptor<Aes128>;
    type Dec = cbc::Decryptor<Aes128>;
    const IV: [u8; 16] = [0x20; 16];

    pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        Enc::new_from_slices(key, &IV)
            .expect("16-byte key/iv")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    pub fn decrypt(key: &[u8], body: &[u8]) -> Option<Vec<u8>> {
        Dec::new_from_slices(key, &IV)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(body)
            .ok()
    }
}

// ---- Windows cipher: AES-256-GCM + DPAPI key (mirrors src-tauri/cookies.rs) ----

#[cfg(target_os = "windows")]
mod cipher {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };
    use anyhow::{anyhow, Context, Result};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::path::Path;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    const DPAPI_TAG: &[u8] = b"DPAPI";

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        getrandom::getrandom(&mut b).expect("getrandom");
        b
    }

    // body = nonce(12) || ciphertext || tag(16)
    pub fn decrypt(key: &[u8], body: &[u8]) -> Option<Vec<u8>> {
        if key.len() != 32 || body.len() < 12 + 16 {
            return None;
        }
        let c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let (nonce, ct) = body.split_at(12);
        c.decrypt(Nonce::from_slice(nonce), ct).ok()
    }

    pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = rand_bytes::<12>();
        let ct = c
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("gcm encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    unsafe fn dpapi(input: &[u8], protect: bool) -> Result<Vec<u8>> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = if protect {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut out_blob,
            )
        } else {
            CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut out_blob,
            )
        };
        if ok == 0 {
            return Err(anyhow!(
                "DPAPI {} failed",
                if protect { "protect" } else { "unprotect" }
            ));
        }
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(out)
    }

    /// Read the profile's os_crypt key, minting+persisting one if absent.
    pub fn os_crypt_key(udd: &Path) -> Result<Vec<u8>> {
        let ls_path = udd.join("Local State");
        if let Some(key) = read_key(&ls_path)? {
            return Ok(key);
        }
        let key = rand_bytes::<32>().to_vec();
        write_key(&ls_path, &key)?;
        Ok(key)
    }

    fn read_key(ls_path: &Path) -> Result<Option<Vec<u8>>> {
        if !ls_path.exists() {
            return Ok(None);
        }
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(ls_path).context("read Local State")?)
                .context("parse Local State")?;
        let enc = match json
            .get("os_crypt")
            .and_then(|o| o.get("encrypted_key"))
            .and_then(|k| k.as_str())
        {
            Some(s) => s,
            None => return Ok(None),
        };
        let blob = STANDARD.decode(enc).context("base64 encrypted_key")?;
        if blob.len() <= DPAPI_TAG.len() || &blob[..DPAPI_TAG.len()] != DPAPI_TAG {
            return Err(anyhow!("encrypted_key missing DPAPI tag"));
        }
        Ok(Some(unsafe { dpapi(&blob[DPAPI_TAG.len()..], false)? }))
    }

    fn write_key(ls_path: &Path, key: &[u8]) -> Result<()> {
        let wrapped = unsafe { dpapi(key, true)? };
        let mut tagged = DPAPI_TAG.to_vec();
        tagged.extend_from_slice(&wrapped);
        let b64 = STANDARD.encode(&tagged);

        let mut json: serde_json::Value = if ls_path.exists() {
            serde_json::from_str(&std::fs::read_to_string(ls_path)?)
                .unwrap_or_else(|_| serde_json::json!({}))
        } else {
            if let Some(p) = ls_path.parent() {
                std::fs::create_dir_all(p).ok();
            }
            serde_json::json!({})
        };
        if !json.is_object() {
            json = serde_json::json!({});
        }
        json["os_crypt"]["encrypted_key"] = serde_json::Value::String(b64);
        std::fs::write(ls_path, serde_json::to_string(&json)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The cross-machine guarantee: a value encrypted under one key decrypts to
    // the same plaintext after being re-encrypted under a different key — this
    // is exactly what a snapshot does (decrypt with source key → plaintext →
    // encrypt with destination key). Exercised on the POSIX cipher.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn rekey_roundtrip_posix() {
        let key_a = LocalCrypt::with_key(vec![1u8; 16]);
        let key_b = LocalCrypt::with_key(vec![2u8; 16]);

        let blob_a = key_a.encrypt_cookie("example.com", "session=abc123");
        let plain = key_a.decrypt_cookie(&blob_a, "");
        assert_eq!(plain, "session=abc123");

        // Re-key: encrypt the recovered plaintext under a different key.
        let blob_b = key_b.encrypt_cookie("example.com", &plain);
        assert_ne!(blob_a, blob_b, "different keys → different ciphertext");
        assert_eq!(key_b.decrypt_cookie(&blob_b, ""), "session=abc123");
        // The wrong key must not recover it.
        assert_ne!(key_a.decrypt_cookie(&blob_b, ""), "session=abc123");
    }

    #[test]
    fn local_cookie_roundtrip() {
        let dir = std::env::temp_dir().join(format!("shardx-oscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = LocalCrypt::open(&dir).unwrap();
        let blob = c.encrypt_cookie("sub.example.com", "tok=ZZZ");
        assert_eq!(&blob[..3], b"v10");
        assert_eq!(c.decrypt_cookie(&blob, ""), "tok=ZZZ");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn secret_roundtrip_no_prefix() {
        let c = LocalCrypt::with_key(vec![7u8; 16]);
        let blob = c.encrypt_secret(b"hunter2");
        assert_eq!(c.decrypt_secret(&blob).unwrap(), b"hunter2");
        // A non-v10 blob is rejected.
        assert!(c.decrypt_secret(b"plain").is_none());
    }

    #[test]
    fn legacy_plain_fallback() {
        let c = LocalCrypt::with_key(vec![3u8; 16]);
        assert_eq!(c.decrypt_cookie(b"not-v10-bytes", "legacy"), "legacy");
    }
}
