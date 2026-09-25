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

use executor::{CommitmentProver, ProofMaker};
use lifecycle::CommitmentArtifacts;

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
            .map_err(|e| std::io::Error::other(format!("csprng: {e}")))?;
        write_new_0600(&self.path_for(job_id), &nonce)?;
        Ok(nonce)
    }

    /// Where a job's committed [`CommitmentArtifacts`] live (PBA-L6b-007).
    pub fn artifacts_path(&self, job_id: u128) -> PathBuf {
        self.dir.join(format!("artifacts-{job_id}.bin"))
    }

    /// PBA-L6b-007 (NA-01 residual): durably persist the job's commitment
    /// artifacts (`proofData = commitment ‖ nonce ‖ output`) `0600` BEFORE the
    /// commitment is emitted. The nonce alone is not enough: after a restart the
    /// executor would otherwise re-run (sampled, non-reproducible) inference and
    /// reveal an output that cannot match the on-chain commitment — a slash.
    ///
    /// Atomic: written to a `0600` temp file, `fsync`ed, then renamed over the
    /// final path, so a crash mid-write never leaves a torn artifacts file.
    pub fn save_artifacts(&self, job_id: u128, art: &CommitmentArtifacts) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        harden_dir_perms(&self.dir)?;
        let final_path = self.artifacts_path(job_id);
        let tmp = self.dir.join(format!("artifacts-{job_id}.bin.tmp"));
        // A stale temp file from an earlier crash is never trusted; replace it.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        write_new_0600(&tmp, &art.proof)?;
        std::fs::rename(&tmp, &final_path)?;
        sync_dir(&self.dir)
    }

    /// Reload a job's persisted artifacts, or `None` if none were saved. The
    /// file is re-verified on load: `commitment == keccak256(output ‖ nonce)`
    /// must hold, and the nonce must equal the job's persisted nonce, else the
    /// file is corrupt and an error is surfaced (never silently re-derived).
    pub fn load_artifacts(&self, job_id: u128) -> std::io::Result<Option<CommitmentArtifacts>> {
        self.load_artifacts_capped(job_id, MAX_ARTIFACTS_BYTES)
    }

    fn load_artifacts_capped(
        &self,
        job_id: u128,
        max: u64,
    ) -> std::io::Result<Option<CommitmentArtifacts>> {
        use std::io::Read;
        let path = self.artifacts_path(job_id);
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut proof = Vec::new();
        f.take(max + 1).read_to_end(&mut proof)?;
        let corrupt = |why: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("persisted artifacts for job {job_id} are corrupt: {why}"),
            )
        };
        if proof.len() as u64 > max {
            return Err(corrupt("oversized"));
        }
        if proof.len() < 64 {
            return Err(corrupt("shorter than commitment ‖ nonce"));
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&proof[32..64]);
        let rebuilt = CommitmentProver.build(&proof[64..], nonce);
        if rebuilt.proof != proof {
            return Err(corrupt("commitment does not match keccak256(output ‖ nonce)"));
        }
        match self.load(job_id)? {
            Some(n) if n == nonce => Ok(Some(rebuilt)),
            _ => Err(corrupt("nonce does not match the persisted commitment nonce")),
        }
    }
}

/// Upper bound on a persisted artifacts file (a model completion plus 64 bytes).
const MAX_ARTIFACTS_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
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
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_new_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
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

    // ── PBA-L6b-007: persisted commitment artifacts (mutation-hardening) ──

    fn art(output: &[u8], nonce: [u8; 32]) -> CommitmentArtifacts {
        CommitmentProver.build(output, nonce)
    }

    #[test]
    fn artifacts_roundtrip_including_empty_output() {
        let store = temp_store("art-rt");
        let n = store.mint(1).unwrap();
        for out in [b"".as_slice(), b"hello".as_slice()] {
            let a = art(out, n);
            store.save_artifacts(1, &a).unwrap();
            assert_eq!(store.load_artifacts(1).unwrap(), Some(a), "len {}", out.len());
        }
        assert_eq!(store.load_artifacts(2).unwrap(), None, "never saved");
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[test]
    fn artifacts_size_cap_is_exact() {
        let store = temp_store("art-cap");
        let n = store.mint(1).unwrap();
        let a = art(b"0123456789", n);
        store.save_artifacts(1, &a).unwrap();
        let len = a.proof.len() as u64;
        assert_eq!(store.load_artifacts_capped(1, len).unwrap(), Some(a));
        assert!(store.load_artifacts_capped(1, len - 1).is_err(), "one byte over the cap");
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[test]
    fn short_artifacts_file_is_corrupt_not_a_panic() {
        let store = temp_store("art-short");
        store.mint(1).unwrap();
        std::fs::write(store.artifacts_path(1), [7u8; 10]).unwrap();
        let r = std::panic::catch_unwind(|| store.load_artifacts(1));
        assert!(matches!(r, Ok(Err(_))), "10-byte file must be an error");
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[test]
    fn tampered_or_foreign_nonce_artifacts_are_rejected() {
        let store = temp_store("art-tamper");
        let n = store.mint(1).unwrap();
        // Output tampered after the commitment was computed.
        let mut a = art(b"out", n);
        let last = a.proof.len() - 1;
        a.proof[last] ^= 1;
        std::fs::write(store.artifacts_path(1), &a.proof).unwrap();
        assert!(store.load_artifacts(1).is_err(), "commitment mismatch");
        // Internally consistent, but committed under a different nonce.
        let foreign = art(b"out", [0x99; 32]);
        assert_ne!(n, [0x99; 32]);
        std::fs::write(store.artifacts_path(1), &foreign.proof).unwrap();
        assert!(store.load_artifacts(1).is_err(), "nonce mismatch");
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_artifacts_file_is_an_error_not_absent() {
        use std::os::unix::fs::PermissionsExt;
        let store = temp_store("art-perm");
        let n = store.mint(1).unwrap();
        store.save_artifacts(1, &art(b"x", n)).unwrap();
        let p = store.artifacts_path(1);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&p).is_ok() {
            // Running as root: permissions are not enforced; nothing to assert.
            let _ = std::fs::remove_dir_all(&store.dir);
            return;
        }
        assert!(
            store.load_artifacts(1).is_err(),
            "an unreadable file must not be reported as 'no artifacts'"
        );
        let _ = std::fs::remove_dir_all(&store.dir);
    }
}
