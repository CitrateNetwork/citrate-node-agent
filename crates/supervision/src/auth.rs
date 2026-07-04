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
//!
//! ## Why a file, not the OS keyring (ENCRYPT-S1 WP-10 threat model)
//!
//! This token is **not** a long-lived secret owned solely by this process — it is
//! an *inter-process* credential. The daemon mints it; a **separate** signing
//! process (`gui-native`) reads the very same bytes back through
//! [`TOKEN_PATH_ENV`] and presents them as `Authorization: Bearer` to reach the
//! loopback surface. The filesystem path *is* the IPC channel. Moving the token
//! into the OS keyring would break that handoff (the peer would have to agree on
//! a keyring service/account and hold Secret-Service access — which headless
//! droplets do not have), so file-passing is the correct and required design
//! here.
//!
//! The security therefore rests entirely on filesystem permissions, which this
//! module enforces on every load-or-create:
//!   * the token file is `0600` (owner read/write only), and
//!   * its parent directory is `0700` (owner-only traversal), so a peer user
//!     cannot even `stat`/replace the file to smuggle in an attacker token.
//! Both are (re)hardened on every run so a loosened inode is repaired at startup.

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
    /// The file is always (re)hardened to `0600` and its parent directory to
    /// `0700` on Unix (see the module-level threat model): the token's only
    /// protection is filesystem permissions, so we repair them on every run.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                let auth = Self::from_token(trimmed);
                if let Some(parent) = path.parent() {
                    harden_dir_perms(parent)?;
                }
                harden_perms(path)?;
                return Ok(auth);
            }
        }
        let auth = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            harden_dir_perms(parent)?;
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

/// Harden the token's parent directory to `0700` (owner-only) so a peer user
/// cannot traverse in to read, replace, or pre-create the token file. A no-op
/// for an empty/relative-root parent (nothing to tighten).
#[cfg(unix)]
fn harden_dir_perms(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    let mut perms = std::fs::metadata(dir)?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
fn harden_dir_perms(_dir: &Path) -> std::io::Result<()> {
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
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700, "token dir must be 0700");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ENCRYPT-S1 WP-10: the token's only protection is filesystem perms, so a
    /// pre-existing, world-accessible dir/file must be repaired to 0700/0600 on
    /// load — not just on first create.
    #[cfg(unix)]
    #[test]
    fn load_or_create_repairs_loose_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "citrate-superv-auth-loose-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("supervision.token");

        // Seed a token file and deliberately loosen both inode's perms.
        std::fs::write(&path, "seededtoken0123456789").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let auth = SupervisionAuth::load_or_create(&path).unwrap();
        assert_eq!(auth.token(), "seededtoken0123456789", "existing token reused");

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "loose token file re-hardened to 0600");
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "loose token dir re-hardened to 0700");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
