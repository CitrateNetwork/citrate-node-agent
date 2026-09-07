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
        // NA-B-007: before trusting a pre-existing token file, refuse to adopt it
        // through a symlink or from an inode we do not own. The module's whole
        // threat model is "security rests on filesystem permissions", but the old
        // path read + `chmod 0600` + `write` all followed symlinks and never
        // checked ownership — so a party who could pre-create the token path (a
        // shared/misconfigured dir, or an operator-supplied
        // `CITRATE_NODE_AGENT_TOKEN_FILE`) could either fix the supervision token
        // or redirect the hardening/write onto an arbitrary file owned by the
        // daemon user.
        if let Some(existing) = read_existing_token(path)? {
            let trimmed = existing.trim();
            if !trimmed.is_empty() {
                let auth = Self::from_token(trimmed);
                if let Some(parent) = path.parent() {
                    harden_dir_perms(parent)?;
                }
                harden_perms(path)?;
                return Ok(auth);
            }
            // A present-but-empty token file is an anomaly; on Unix we refuse to
            // overwrite it in place (it may be a symlink target / foreign inode)
            // and fail closed rather than silently replace it.
            #[cfg(unix)]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "supervision token file {} exists but is empty; refusing to overwrite in place",
                    path.display()
                ),
            ));
        }
        let auth = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            harden_dir_perms(parent)?;
        }
        create_new_token_file(path, auth.token())?;
        harden_perms(path)?;
        Ok(auth)
    }
}

/// Read a pre-existing token, fail-closed on a symlink or foreign-owned inode.
///
/// Returns `Ok(None)` when the path does not exist (the create branch takes
/// over), `Ok(Some(contents))` when a safe regular file is present, and `Err`
/// when the inode is a symlink or is owned by another uid (NA-B-007). On
/// non-Unix targets there is no symlink/uid concept here, so it simply reads.
#[cfg(unix)]
fn read_existing_token(path: &Path) -> std::io::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "supervision token path {} is a symlink; refusing to follow it (NA-B-007)",
                path.display()
            ),
        ));
    }
    // Trust only an inode we own. `geteuid` is the daemon's effective uid.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "supervision token file {} is owned by uid {} not {}; refusing to adopt it (NA-B-007)",
                path.display(),
                meta.uid(),
                euid
            ),
        ));
    }
    // Open with O_NOFOLLOW so a swap-to-symlink after the stat is also refused.
    match open_no_follow(path) {
        Ok(mut f) => {
            use std::io::Read;
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(Some(s))
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn read_existing_token(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Create the token file, failing if anything already exists at the path
/// (`create_new`) and never following a symlink (`O_NOFOLLOW`), with `0600` from
/// the moment of creation so there is no window at the default umask (NA-B-007).
#[cfg(unix)]
fn create_new_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(token.as_bytes())
}

#[cfg(not(unix))]
fn create_new_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    std::fs::write(path, token)
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

    /// NA-B-007: a symlink at the token path must be refused, not followed —
    /// adopting the target's contents would let a pre-planter fix the token, and
    /// the subsequent `chmod 0600` / write would land on an arbitrary file owned
    /// by the daemon user.
    #[cfg(unix)]
    #[test]
    fn load_or_create_refuses_a_symlinked_token_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "citrate-superv-auth-symlink-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // A victim file the attacker wants chmod'd/overwritten, with contents an
        // attacker would want adopted as the token.
        let victim = dir.join("victim.secret");
        std::fs::write(&victim, "attacker-chosen-token-0000").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        // The token path is a symlink to the victim.
        let token_path = dir.join("supervision.token");
        std::os::unix::fs::symlink(&victim, &token_path).unwrap();

        let err = match SupervisionAuth::load_or_create(&token_path) {
            Ok(_) => panic!("expected load_or_create to refuse"),
            Err(e) => e,
        };
        assert!(
            matches!(err.kind(), std::io::ErrorKind::InvalidData),
            "symlinked token path must be refused, got {err:?}"
        );
        // The victim was neither adopted nor hardened/overwritten.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "attacker-chosen-token-0000");
        let vmode = std::fs::metadata(&victim).unwrap().permissions().mode();
        assert_eq!(vmode & 0o777, 0o644, "victim perms untouched (no chmod-through-symlink)");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NA-B-007: the create path uses `create_new` + `O_NOFOLLOW`, so a symlink
    /// pre-planted where the token would be created is a hard error (the write
    /// cannot be redirected onto the symlink target).
    #[cfg(unix)]
    #[test]
    fn create_refuses_to_write_through_a_pre_planted_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "citrate-superv-auth-createlink-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("redirect.target"); // does not exist yet
        let token_path = dir.join("supervision.token");
        std::os::unix::fs::symlink(&target, &token_path).unwrap();

        let err = match SupervisionAuth::load_or_create(&token_path) {
            Ok(_) => panic!("expected load_or_create to refuse"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::AlreadyExists
            ),
            "a pre-planted symlink at the create path must be refused, got {err:?}"
        );
        // Nothing was written to the redirect target.
        assert!(!target.exists(), "O_NOFOLLOW/create_new must not create the symlink target");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
