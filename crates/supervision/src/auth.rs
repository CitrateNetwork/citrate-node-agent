//! Per-instance bearer token for the supervision surface (FUA-NODE-AGENT-01/02).
//!
//! The supervision HTTP surface exposes the daemon's unsigned chain writes
//! (`GET /signature-requests`, whose `calldata` carries the pre-reveal
//! commitment secret for `submitResult`) and lets a caller pause the node or
//! mark a write observed. The loopback bind alone is NOT sufficient: *any* local
//! process — and, for the no-preflight `/pause`/`/resume` POSTs, any web page the
//! operator visits — could reach it. This module mints a 256-bit random token at
//! startup, persists it `0600`, and the server requires it as a
//! `Authorization: Bearer <token>` on every endpoint except `/health`. The
//! signing surface (gui-native) reads the same file and presents the token, so a
//! browser (which cannot read a local file) and an unprivileged process (which
//! cannot read a `0600` file owned by the daemon user) are both shut out.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use subtle::ConstantTimeEq;

/// Env var pointing at the token file (shared contract with gui-native).
pub const TOKEN_PATH_ENV: &str = "CITRATE_NODE_AGENT_TOKEN_FILE";

/// The per-instance supervision bearer token.
#[derive(Clone)]
pub struct SupervisionAuth {
    token: Arc<str>,
}

impl SupervisionAuth {
    /// Build from an existing token string (loaded from disk, or a test fixture).
    pub fn from_token(token: impl Into<String>) -> Self {
        Self {
            token: Arc::from(token.into().into_boxed_str()),
        }
    }

    /// Mint a fresh 256-bit random token (hex-encoded, 64 chars).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        Self::from_token(hex_encode(&bytes))
    }

    /// The raw token string (for the daemon to log its path, never the value).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Constant-time check of a presented bearer token. Length mismatch is an
    /// immediate (still-safe) reject; equal-length inputs are compared in
    /// constant time so the surface leaks no timing signal about the token.
    pub fn verify(&self, presented: &str) -> bool {
        let expected = self.token.as_bytes();
        let got = presented.as_bytes();
        if expected.len() != got.len() {
            return false;
        }
        expected.ct_eq(got).into()
    }

    /// Load the token from `path`, or generate + persist it if absent/empty.
    /// The file is always (re)hardened to `0600` on Unix.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                let auth = Self::from_token(trimmed);
                harden_perms(path)?;
                return Ok(auth);
            }
        }
        let auth = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, auth.token())?;
        harden_perms(path)?;
        Ok(auth)
    }
}

/// Resolve the token-file path: `CITRATE_NODE_AGENT_TOKEN_FILE` if set, else
/// `$HOME/.citrate/node-agent/supervision.token`.
pub fn default_token_path() -> PathBuf {
    if let Ok(p) = std::env::var(TOKEN_PATH_ENV) {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".citrate")
        .join("node-agent")
        .join("supervision.token")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(unix)]
fn harden_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn harden_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_64_hex_chars() {
        let a = SupervisionAuth::generate();
        assert_eq!(a.token().len(), 64);
        assert!(a.token().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_tokens_differ() {
        assert_ne!(
            SupervisionAuth::generate().token(),
            SupervisionAuth::generate().token()
        );
    }

    #[test]
    fn verify_accepts_exact_and_rejects_others() {
        let a = SupervisionAuth::from_token("deadbeef");
        assert!(a.verify("deadbeef"));
        assert!(!a.verify("deadbedf")); // one nibble off, same length
        assert!(!a.verify("deadbe")); // shorter
        assert!(!a.verify("deadbeef00")); // longer
        assert!(!a.verify("")); // empty
    }

    #[test]
    fn load_or_create_persists_and_reuses() {
        let dir = std::env::temp_dir().join(format!(
            "citrate-superv-auth-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        let path = dir.join("supervision.token");

        let first = SupervisionAuth::load_or_create(&path).unwrap();
        assert_eq!(first.token().len(), 64);

        // Second load reads the SAME token back (stable across restarts).
        let second = SupervisionAuth::load_or_create(&path).unwrap();
        assert_eq!(first.token(), second.token());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token file must be 0600");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
