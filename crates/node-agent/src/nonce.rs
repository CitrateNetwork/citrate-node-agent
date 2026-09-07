//! `nonce` — per-job commitment nonces, minted once per job and persisted.
//!
//! The Commitment tier commits `keccak256(output ‖ nonce)` and later reveals the
//! nonce on-chain in `submitResult.proofData`. Two properties matter:
//!
//! * **Per-job uniqueness (NA-B-008).** The nonce becomes public the instant the
//!   first job's `submitResult` lands. A nonce reused for a second job would let
//!   an observer who can predict/influence the second output precompute the
//!   commitment, breaking the commit-before-reveal property. The daemon used to
//!   mint one nonce per *process* (`live::random_nonce()` at startup) and reuse
//!   it — safe only because the executor is hard-wired to one job today. This
//!   store mints a **fresh** nonce per `job_id`, so the reuse cannot land when
//!   multi-job execution arrives.
//!
//! * **Restart stability (NA-01).** The nonce was held only in memory. After a
//!   crash between commit and result, a restart minted a *new* nonce, reset the
//!   per-job progress, read `committed = true` back from chain, re-ran inference
//!   and revealed `(output, new_nonce)` — which cannot reproduce the stored
//!   commitment, so the verifier rejects it and the provider self-slashes. This
//!   store **persists** each job's nonce (0600) so a restart reuses the same
//!   one; and when the persisted nonce is gone but the job is already committed,
//!   the caller refuses to reveal a mismatch rather than emit a doomed
//!   `submitResult` (see `execution::JobExecutor::step`).

use std::path::{Path, PathBuf};

/// Persists one 32-byte commitment nonce per job id under a `0700` state dir.
#[derive(Debug, Clone)]
pub struct NonceStore {
    dir: PathBuf,
}

/// Default per-job nonce state dir: `CITRATE_NODE_AGENT_STATE_DIR` if set, else
/// `$HOME/.citrate/node-agent/nonces` (mirrors the supervision token layout).
pub fn default_state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CITRATE_NODE_AGENT_STATE_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p).join("nonces");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".citrate")
        .join("node-agent")
        .join("nonces")
}

impl NonceStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path_for(&self, job_id: u128) -> PathBuf {
        self.dir.join(format!("nonce-{job_id}.bin"))
    }

    /// Return the persisted nonce for `job_id`, or `None` if none is stored.
    ///
    /// A stored file that is not exactly 32 bytes is treated as corrupt and
    /// surfaced as an error rather than silently regenerated (regenerating after
    /// a commit is exactly the NA-01 self-slash).
    pub fn load(&self, job_id: u128) -> std::io::Result<Option<[u8; 32]>> {
        let path = self.path_for(job_id);
        match std::fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut n = [0u8; 32];
                n.copy_from_slice(&bytes);
                Ok(Some(n))
            }
            Ok(bytes) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "persisted nonce for job {job_id} is {} bytes, expected 32 (corrupt)",
                    bytes.len()
                ),
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Mint a fresh CSPRNG nonce for `job_id` and persist it `0600`. Fails if a
    /// nonce already exists for the job (`create_new`) — callers `load` first and
    /// mint only on a miss, so an existing file means a concurrent mint and must
    /// not be clobbered.
    pub fn mint(&self, job_id: u128) -> std::io::Result<[u8; 32]> {
        std::fs::create_dir_all(&self.dir)?;
        harden_dir_perms(&self.dir)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("csprng: {e}")))?;
        write_new_0600(&self.path_for(job_id), &nonce)?;
        Ok(nonce)
    }

}

#[cfg(unix)]
fn write_new_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_new_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(unix)]
fn harden_dir_perms(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
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

    fn temp_store(tag: &str) -> NonceStore {
        let dir = std::env::temp_dir().join(format!(
            "citrate-nonce-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        NonceStore::new(dir)
    }

    // NA-B-008: distinct jobs get distinct nonces (no cross-job reuse).
    #[test]
    fn distinct_jobs_get_distinct_nonces() {
        let store = temp_store("distinct");
        let a = store.mint(1).unwrap();
        let b = store.mint(2).unwrap();
        assert_ne!(a, b, "each job id must mint its own nonce");
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    // NA-01: a job's nonce survives a "restart" (a fresh store over the same
    // dir), so the reveal reproduces the commitment instead of self-slashing.
    #[test]
    fn nonce_is_stable_across_reloads() {
        let store = temp_store("stable");
        let first = store.mint(7).unwrap();
        // Simulate a restart: a brand-new store instance over the same dir.
        let reloaded = NonceStore::new(store.dir.clone());
        assert_eq!(reloaded.load(7).unwrap(), Some(first), "restart reuses the nonce");
        // A job that was never minted has no persisted nonce.
        assert_eq!(reloaded.load(999).unwrap(), None);
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[cfg(unix)]
    #[test]
    fn minted_nonce_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let store = temp_store("perms");
        store.mint(3).unwrap();
        let mode = std::fs::metadata(store.path_for(3)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "nonce file must be 0600");
        let _ = std::fs::remove_dir_all(&store.dir);
    }
}
