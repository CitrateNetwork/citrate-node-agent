//! `models` — verified IPFS-fetch model provisioning (`CID → fetch → verify → cache`).
//!
//! Given a job's resolved [`chainio::model_registry::ModelInfo`] (the `ipfsCID`
//! and `isActive`), bring the weights onto local disk, integrity-check them, and
//! cache them so a repeat job for the same model short-circuits the download.
//!
//! ## Honest integrity model
//! A provider needs the *right* weights *present right now* to run one job — a
//! fetch + integrity check, not a storage-market proof (that durable, rewarded
//! path is PIN's sealed-PoRep). What we can guarantee today, with the reads the
//! chain actually exposes and no new crypto deps:
//! - **`isActive`** — never run a deactivated model.
//! - **CID-addressed fetch** — the weights are requested *by their CID* from a
//!   content-addressed transport, which self-verifies the multihash at the IPFS
//!   layer ([`Integrity::CidTransportOnly`]).
//! - **`sizeBytes`** cross-check **when known** — `ModelRegistry.getModel` does
//!   *not* return `sizeBytes`, so the caller can pass it only if it read the full
//!   `models(bytes32)` struct; when supplied we reject a length mismatch
//!   ([`Integrity::SizeAndCidTransport`]).
//!
//! Recomputing the IPFS CID/UnixFS multihash from the raw bytes (full content
//! binding without trusting the transport) needs sha2 + a UnixFS chunker — out of
//! scope here and logged as tech-debt. We do **not** pretend `ModelRegistry.modelHash`
//! is a content digest (it is a registration keccak of `owner‖name‖…`).

use std::path::{Path, PathBuf};

/// A model present + integrity-checked on local disk, ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedModel {
    /// The job's `modelHash` (the registry key / cache key).
    pub model_hash: [u8; 32],
    /// Where the weights live on disk.
    pub path: PathBuf,
    /// Bytes on disk.
    pub bytes_len: u64,
    /// Which integrity guarantee actually held (honest about strength).
    pub integrity: Integrity,
}

/// The integrity guarantee a [`ProvisionedModel`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// Length matched the registry `sizeBytes` AND the fetch was CID-addressed.
    SizeAndCidTransport,
    /// CID-addressed fetch only (no `sizeBytes` was available to cross-check).
    CidTransportOnly,
}

/// Why provisioning failed.
#[derive(Debug)]
pub enum ProvisionError {
    /// The model is deactivated on-chain; refuse to run it.
    Inactive,
    /// The registry returned an empty `ipfsCID`.
    EmptyCid,
    /// Fetched byte length did not match the registry `sizeBytes`.
    SizeMismatch { expected: u64, got: u64 },
    /// The weight source failed to deliver the CID.
    Fetch(String),
    /// A local cache I/O error.
    Cache(String),
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProvisionError::Inactive => write!(f, "model is deactivated on-chain"),
            ProvisionError::EmptyCid => write!(f, "registry returned an empty ipfsCID"),
            ProvisionError::SizeMismatch { expected, got } => {
                write!(f, "size mismatch: expected {expected} bytes, got {got}")
            }
            ProvisionError::Fetch(m) => write!(f, "weight fetch failed: {m}"),
            ProvisionError::Cache(m) => write!(f, "model cache error: {m}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

/// Abstracts fetching a CID's bytes. The real impl ([`IpfsGatewaySource`]) GETs
/// an IPFS gateway by CID; tests use an in-memory fake. Async (network) lives
/// behind the trait so the provisioning logic is unit-tested fully offline.
pub trait WeightSource {
    /// Fetch the full byte payload addressed by `cid`.
    fn fetch(
        &self,
        cid: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ProvisionError>> + Send;
}

/// Cache file name for a model: lowercase hex of its `modelHash`, `.bin`.
fn cache_file(cache_dir: &Path, model_hash: &[u8; 32]) -> PathBuf {
    let mut name = String::with_capacity(64 + 4);
    for b in model_hash {
        name.push_str(&format!("{b:02x}"));
    }
    name.push_str(".bin");
    cache_dir.join(name)
}

/// Provision a model: return a cached copy if present (idempotent), else fetch by
/// CID, integrity-check, and cache. `expected_size` enables the `sizeBytes`
/// cross-check when the caller has it (e.g. from the full `models` struct).
pub async fn provision<S: WeightSource + Sync>(
    model_hash: [u8; 32],
    ipfs_cid: &str,
    is_active: bool,
    expected_size: Option<u64>,
    cache_dir: &Path,
    source: &S,
) -> Result<ProvisionedModel, ProvisionError> {
    if !is_active {
        return Err(ProvisionError::Inactive);
    }
    if ipfs_cid.is_empty() {
        return Err(ProvisionError::EmptyCid);
    }

    let integrity = match expected_size {
        Some(_) => Integrity::SizeAndCidTransport,
        None => Integrity::CidTransportOnly,
    };
    let path = cache_file(cache_dir, &model_hash);

    // Cache hit: present and (when we know the size) the right size → reuse.
    if let Ok(meta) = std::fs::metadata(&path) {
        let len = meta.len();
        if expected_size.is_none_or(|sz| sz == len) {
            return Ok(ProvisionedModel {
                model_hash,
                path,
                bytes_len: len,
                integrity,
            });
        }
        // Stale/corrupt cache (wrong size) — fall through and re-fetch.
    }

    let bytes = source.fetch(ipfs_cid).await?;
    if let Some(sz) = expected_size {
        if bytes.len() as u64 != sz {
            return Err(ProvisionError::SizeMismatch {
                expected: sz,
                got: bytes.len() as u64,
            });
        }
    }

    std::fs::create_dir_all(cache_dir).map_err(|e| ProvisionError::Cache(e.to_string()))?;
    std::fs::write(&path, &bytes).map_err(|e| ProvisionError::Cache(e.to_string()))?;

    Ok(ProvisionedModel {
        model_hash,
        path,
        bytes_len: bytes.len() as u64,
        integrity,
    })
}

/// Real weight source: GET `{gateway}/ipfs/{cid}` from a content-addressed IPFS
/// gateway. The gateway verifies the CID↔content binding at the IPFS layer.
pub struct IpfsGatewaySource {
    gateway: String,
    client: reqwest::Client,
}

impl IpfsGatewaySource {
    /// `gateway` is the base URL, e.g. `http://127.0.0.1:8080` (a local Kubo
    /// node) — prefer a *local* trusted node so the CID self-verification is
    /// meaningful.
    pub fn new(gateway: impl Into<String>) -> Self {
        Self {
            gateway: gateway.into(),
            client: reqwest::Client::new(),
        }
    }
}

impl WeightSource for IpfsGatewaySource {
    async fn fetch(&self, cid: &str) -> Result<Vec<u8>, ProvisionError> {
        let url = format!("{}/ipfs/{}", self.gateway.trim_end_matches('/'), cid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ProvisionError::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ProvisionError::Fetch(format!("gateway status {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ProvisionError::Fetch(e.to_string()))?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory fake: serves fixed bytes for any CID and counts fetches.
    struct FakeSource {
        bytes: Vec<u8>,
        fetches: Mutex<usize>,
    }
    impl FakeSource {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                fetches: Mutex::new(0),
            }
        }
        fn fetch_count(&self) -> usize {
            *self.fetches.lock().unwrap()
        }
    }
    impl WeightSource for FakeSource {
        async fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProvisionError> {
            *self.fetches.lock().unwrap() += 1;
            Ok(self.bytes.clone())
        }
    }

    fn tmp(sub: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("citrate-exec-{sub}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn provisions_and_caches_with_size_match() {
        let dir = tmp("size-match");
        let src = FakeSource::new(vec![0xab; 100]);
        let m = provision([0x01; 32], "bafycid", true, Some(100), &dir, &src)
            .await
            .unwrap();
        assert_eq!(m.bytes_len, 100);
        assert_eq!(m.integrity, Integrity::SizeAndCidTransport);
        assert!(m.path.exists());
        assert_eq!(src.fetch_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn size_mismatch_is_rejected() {
        let dir = tmp("size-mismatch");
        let src = FakeSource::new(vec![0xab; 50]);
        let err = provision([0x02; 32], "bafycid", true, Some(100), &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProvisionError::SizeMismatch { expected: 100, got: 50 }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn inactive_model_is_refused_without_fetching() {
        let dir = tmp("inactive");
        let src = FakeSource::new(vec![0u8; 10]);
        let err = provision([0x03; 32], "bafycid", false, None, &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::Inactive));
        assert_eq!(src.fetch_count(), 0);
    }

    #[tokio::test]
    async fn empty_cid_is_refused() {
        let dir = tmp("empty-cid");
        let src = FakeSource::new(vec![0u8; 10]);
        let err = provision([0x04; 32], "", true, None, &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::EmptyCid));
        assert_eq!(src.fetch_count(), 0);
    }

    #[tokio::test]
    async fn cache_hit_short_circuits_fetch() {
        let dir = tmp("cache-hit");
        let src = FakeSource::new(vec![0xcd; 64]);
        let hash = [0x05; 32];
        // First call fetches + caches.
        provision(hash, "bafycid", true, Some(64), &dir, &src)
            .await
            .unwrap();
        assert_eq!(src.fetch_count(), 1);
        // Second call for the same model hits the cache — no new fetch.
        let m2 = provision(hash, "bafycid", true, Some(64), &dir, &src)
            .await
            .unwrap();
        assert_eq!(src.fetch_count(), 1);
        assert_eq!(m2.bytes_len, 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_size_yields_cid_transport_only() {
        let dir = tmp("no-size");
        let src = FakeSource::new(vec![0x11; 8]);
        let m = provision([0x06; 32], "bafycid", true, None, &dir, &src)
            .await
            .unwrap();
        assert_eq!(m.integrity, Integrity::CidTransportOnly);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
