//! `models` — verified IPFS-fetch model provisioning (`CID → fetch → verify → cache`).
//!
//! Given a job's resolved [`chainio::model_registry::ModelInfo`] (the `ipfsCID`
//! and `isActive`), bring the weights onto local disk, integrity-check them, and
//! cache them so a repeat job for the same model short-circuits the download.
//!
//! ## Integrity model — SECREM-01 SVC-2 (pre-audit 2026-06-09)
//! Integrity must come from **local recomputation, never from the transport**.
//! The pre-audit found that trusting the gateway's CID↔content binding lets a
//! compromised or MITM'd gateway serve poisoned weights of matching size
//! (corrupted marketplace inference + a parser-RCE surface). Provisioning is
//! therefore gated on a locally verifiable sha-256 commitment:
//! - **`isActive`** — never run a deactivated model.
//! - **Caller-supplied digest** ([`Integrity::Sha256Verified`]) — when the
//!   caller has a trusted `weights_sha256` (registry read / node config), the
//!   downloaded bytes are hashed locally and must match. Strongest path.
//! - **Self-verifying CID** ([`Integrity::CidSha256Verified`]) — a CIDv1
//!   `raw`-codec sha2-256 CID (`bafkrei…`) embeds the sha-256 of the raw bytes;
//!   we decode it and verify the download against it locally. Equivalent
//!   strength, no extra registry field needed.
//! - **Neither available → fail closed** ([`ProvisionError::Unverifiable`]).
//!   CIDv0 (`Qm…`) / dag-pb CIDs hash the UnixFS DAG, not the raw bytes;
//!   recomputing them needs a chunker we deliberately do not ship, so they are
//!   refused unless a `weights_sha256` accompanies them.
//! - **`sizeBytes`** cross-check **when known** — cheap pre-hash reject.
//!
//! On any digest mismatch the artifact is deleted, a hard error is returned
//! (the bytes are never used, cached, or executed), and the event is logged
//! loudly. We do **not** pretend `ModelRegistry.modelHash` is a content digest
//! (it is a registration keccak of `owner‖name‖…`).

use sha2::{Digest, Sha256};
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
///
/// SECREM-01 SVC-2 (pre-audit 2026-06-09): every variant means the sha-256 of
/// the bytes on disk was recomputed locally and matched a commitment that did
/// not come from the transport. The pre-fix "transport-only" variants are gone:
/// unverifiable provisioning is now a hard error, not a weaker success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// sha-256 of the bytes matched the caller-supplied digest
    /// (`weights_sha256` from the registry read or node config).
    Sha256Verified,
    /// sha-256 of the bytes matched the digest embedded in a self-verifying
    /// CIDv1 `raw`-codec sha2-256 CID, decoded and compared locally.
    CidSha256Verified,
}

/// Why provisioning failed.
#[derive(Debug)]
pub enum ProvisionError {
    /// The model is deactivated on-chain; refuse to run it.
    Inactive,
    /// The registry returned an empty `ipfsCID`.
    EmptyCid,
    /// FUA-NODE-AGENT-05 (SECREM-02 WP 7.4): the on-chain `ipfsCID` is not a
    /// bare CIDv0/CIDv1 identifier (traversal chars, wrong alphabet, wrong
    /// shape). Refused before any URL construction or fetch.
    InvalidCid { cid: String },
    /// SECREM-01 SVC-2: no locally verifiable commitment exists — the caller
    /// supplied no `weights_sha256` and the CID is not a self-verifying
    /// CIDv1 raw sha2-256 CID. Fail closed before fetching anything.
    Unverifiable { cid: String },
    /// Fetched byte length did not match the registry `sizeBytes`.
    SizeMismatch { expected: u64, got: u64 },
    /// SECREM-01 SVC-2: locally recomputed sha-256 of the downloaded bytes did
    /// not match the expected commitment. The artifact was discarded.
    DigestMismatch {
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// The weight source failed to deliver the CID.
    Fetch(String),
    /// A local cache I/O error.
    Cache(String),
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProvisionError::Inactive => write!(f, "model is deactivated on-chain"),
            ProvisionError::EmptyCid => write!(f, "registry returned an empty ipfsCID"),
            ProvisionError::InvalidCid { cid } => write!(
                f,
                "invalid model CID {cid:?}: not a bare CIDv0 (Qm…, base58btc) or CIDv1 (b…, base32lower) identifier; refused before URL construction (FUA-NODE-AGENT-05)"
            ),
            ProvisionError::Unverifiable { cid } => write!(
                f,
                "no local integrity commitment for CID {cid}: supply weights_sha256 or use a CIDv1 raw sha2-256 CID (SVC-2 fail-closed)"
            ),
            ProvisionError::SizeMismatch { expected, got } => {
                write!(f, "size mismatch: expected {expected} bytes, got {got}")
            }
            ProvisionError::DigestMismatch { expected, got } => write!(
                f,
                "weights sha-256 mismatch: expected {}, got {} (artifact discarded; SVC-2)",
                hex32(expected),
                hex32(got)
            ),
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

/// Locally recompute the sha-256 of `bytes` (SECREM-01 SVC-2: the only digest
/// we trust is the one we compute ourselves).
pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// RFC 4648 lowercase base32 (no padding) decode — the multibase `b` alphabet
/// used by CIDv1. Returns `None` on any non-alphabet character.
fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u64;
        acc = (acc << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    // Trailing bits must be zero padding (canonical encoding).
    if nbits >= 5 || acc != 0 {
        return None;
    }
    Some(out)
}

/// FUA-NODE-AGENT-05 (SECREM-02 WP 7.4): shape-validate an on-chain `ipfsCID`
/// **before** it is interpolated into a gateway URL. The CID string is fully
/// attacker-controlled (any model owner registers it on-chain), and unvalidated
/// it can carry `../`, `?`, `#`, or `%2f` and escape the gateway's `/ipfs/`
/// path (path traversal / limited SSRF). Accepted shapes — both are single
/// URL-safe path segments by construction:
/// - **CIDv0**: exactly 46 chars, `Qm` + 44 base58btc chars (no `0OIl`).
/// - **CIDv1**, multibase `b` (base32lower): `b` + `[a-z2-7]+` that decodes
///   canonically (zero padding bits) to `<version=0x01>…` with at least
///   version + codec + multihash code + length bytes.
///
/// Anything else — including other multibases — is refused fail-closed;
/// re-encode the CID as base32lower CIDv1 (`ipfs cid format -b base32`).
pub fn validate_cid(cid: &str) -> bool {
    // CIDv0: "Qm" + 44 base58btc chars.
    if cid.len() == 46 && cid.starts_with("Qm") {
        return cid.bytes().all(|b| {
            matches!(b, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
        });
    }
    // CIDv1 multibase `b`: base32lower payload decoding to version byte 0x01.
    if let Some(rest) = cid.strip_prefix('b') {
        if let Some(bytes) = base32_lower_decode(rest) {
            // version + codec + multihash (code, length) is the minimum frame.
            return bytes.len() >= 4 && bytes[0] == 0x01;
        }
    }
    false
}

/// If `cid` is a **self-verifying** CID — CIDv1, multibase `b` (base32lower),
/// codec `raw` (0x55), multihash sha2-256 (0x12, len 32) — return the sha-256
/// of the raw content it commits to. CIDv0 / dag-pb CIDs hash the UnixFS DAG,
/// not the raw bytes, and are NOT locally recomputable here → `None`.
fn cid_embedded_sha256(cid: &str) -> Option<[u8; 32]> {
    let rest = cid.strip_prefix('b')?; // multibase base32lower
    let bytes = base32_lower_decode(rest)?;
    // <version=0x01><codec=0x55 raw><mh code=0x12 sha2-256><mh len=0x20><digest:32>
    if bytes.len() == 36 && bytes[0] == 0x01 && bytes[1] == 0x55 && bytes[2] == 0x12 && bytes[3] == 0x20
    {
        let mut d = [0u8; 32];
        d.copy_from_slice(&bytes[4..36]);
        Some(d)
    } else {
        None
    }
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

/// Provision a model: return a cached copy if present (idempotent), else fetch
/// by CID, integrity-check, and cache.
///
/// SECREM-01 SVC-2 (pre-audit 2026-06-09): the weights' sha-256 is recomputed
/// **locally** and compared against a commitment that does not come from the
/// transport — `expected_sha256` (registry/config `weights_sha256`) when the
/// caller has it, else the digest embedded in a self-verifying CIDv1 raw
/// sha2-256 CID. If neither exists, provisioning fails closed *before* any
/// network fetch. A digest mismatch deletes the artifact and hard-errors; the
/// bytes are never used. `expected_size` remains a cheap pre-hash cross-check.
pub async fn provision<S: WeightSource + Sync>(
    model_hash: [u8; 32],
    ipfs_cid: &str,
    is_active: bool,
    expected_size: Option<u64>,
    expected_sha256: Option<[u8; 32]>,
    cache_dir: &Path,
    source: &S,
) -> Result<ProvisionedModel, ProvisionError> {
    if !is_active {
        return Err(ProvisionError::Inactive);
    }
    if ipfs_cid.is_empty() {
        return Err(ProvisionError::EmptyCid);
    }
    // FUA-NODE-AGENT-05: refuse a malformed / traversal-shaped CID before any
    // URL construction or fetch — the digest below gates *content*, not the
    // URL the attacker-registered CID would steer the fetch to.
    if !validate_cid(ipfs_cid) {
        eprintln!(
            "SECURITY [FUA-NODE-AGENT-05]: refusing model CID {ipfs_cid:?}: not a bare CIDv0/CIDv1 identifier (possible gateway path traversal)"
        );
        return Err(ProvisionError::InvalidCid {
            cid: ipfs_cid.to_string(),
        });
    }

    // SECREM-01 SVC-2: resolve the local integrity commitment BEFORE any fetch.
    // No commitment → no download (fail closed).
    let (expected_digest, integrity) = match expected_sha256 {
        Some(d) => (d, Integrity::Sha256Verified),
        None => match cid_embedded_sha256(ipfs_cid) {
            Some(d) => (d, Integrity::CidSha256Verified),
            None => {
                eprintln!(
                    "SECURITY [SVC-2]: refusing to fetch model CID {ipfs_cid}: no weights_sha256 supplied and the CID is not self-verifying (CIDv1 raw sha2-256)"
                );
                return Err(ProvisionError::Unverifiable {
                    cid: ipfs_cid.to_string(),
                });
            }
        },
    };

    let path = cache_file(cache_dir, &model_hash);

    // Cache hit: re-verify the digest of what's on disk (a cached file is just
    // an earlier download — it gets no integrity pass). Mismatch → delete and
    // fall through to a fresh, verified fetch.
    if let Ok(cached) = std::fs::read(&path) {
        let len = cached.len() as u64;
        if expected_size.is_none_or(|sz| sz == len) && sha256_digest(&cached) == expected_digest {
            return Ok(ProvisionedModel {
                model_hash,
                path,
                bytes_len: len,
                integrity,
            });
        }
        // SECREM-01 SVC-2: poisoned/stale cache — discard it loudly.
        eprintln!(
            "SECURITY [SVC-2]: cached weights at {} failed local sha-256/size verification; deleting and re-fetching",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
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

    // SECREM-01 SVC-2: recompute the content hash locally BEFORE the bytes are
    // cached or used. Integrity comes from this recomputation, never from the
    // gateway. On mismatch: drop the bytes, hard error, no fallback.
    let got = sha256_digest(&bytes);
    if got != expected_digest {
        eprintln!(
            "SECURITY [SVC-2]: downloaded weights for CID {ipfs_cid} failed local sha-256 verification (expected {}, got {}); artifact discarded — possible gateway compromise or MITM",
            hex32(&expected_digest),
            hex32(&got)
        );
        return Err(ProvisionError::DigestMismatch {
            expected: expected_digest,
            got,
        });
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

/// Real weight source: GET `{gateway}/ipfs/{cid}` from an IPFS gateway.
/// SECREM-01 SVC-2: the gateway is treated as an untrusted transport — the
/// bytes it returns are verified by [`provision`]'s local sha-256 recomputation,
/// never by trusting the gateway's CID↔content binding.
/// Default hard ceiling on a single weight fetch (8 GiB). Overridable via
/// `CITRATE_MAX_WEIGHT_BYTES`. FUA-NODE-AGENT-04: bounds the body read so a
/// malicious/compromised gateway can't OOM (or disk-fill) the daemon with a
/// multi-GB response *before* the size/digest check runs.
pub const DEFAULT_MAX_WEIGHT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub struct IpfsGatewaySource {
    gateway: String,
    client: reqwest::Client,
    max_bytes: u64,
}

impl IpfsGatewaySource {
    /// `gateway` is the base URL, e.g. `http://127.0.0.1:8080` (a local Kubo
    /// node). Even a local node is verified-after-download (SVC-2).
    ///
    /// FUA-NODE-AGENT-06 (SECREM-02 WP 7.4): the gateway URL is validated by
    /// [`chainio::outbound::validate_outbound_url`] — plaintext `http://` is
    /// only accepted for loopback (the local-Kubo posture above); a remote
    /// gateway must be `https://`. Fail closed at construction.
    pub fn new(gateway: impl Into<String>) -> Result<Self, chainio::outbound::OutboundUrlError> {
        let gateway = gateway.into();
        chainio::outbound::validate_outbound_url(&gateway)?;
        let max_bytes = std::env::var("CITRATE_MAX_WEIGHT_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_WEIGHT_BYTES);
        Ok(Self {
            gateway,
            client: reqwest::Client::new(),
            max_bytes,
        })
    }
}

impl WeightSource for IpfsGatewaySource {
    async fn fetch(&self, cid: &str) -> Result<Vec<u8>, ProvisionError> {
        // FUA-NODE-AGENT-05: defense in depth below `provision` — never build
        // a gateway URL from a non-CID identifier (`../` would escape /ipfs/).
        if !validate_cid(cid) {
            return Err(ProvisionError::InvalidCid {
                cid: cid.to_string(),
            });
        }
        let url = format!("{}/ipfs/{}", self.gateway.trim_end_matches('/'), cid);
        let mut resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ProvisionError::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ProvisionError::Fetch(format!("gateway status {}", resp.status())));
        }
        // FUA-NODE-AGENT-04: reject early on an oversized Content-Length, then
        // stream with a running cap so an unbounded/chunked body can't OOM us.
        if let Some(len) = resp.content_length() {
            if len > self.max_bytes {
                return Err(ProvisionError::Fetch(format!(
                    "weight too large: Content-Length {len} > {} cap",
                    self.max_bytes
                )));
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProvisionError::Fetch(e.to_string()))?
        {
            if buf.len() as u64 + chunk.len() as u64 > self.max_bytes {
                return Err(ProvisionError::Fetch(format!(
                    "weight exceeds {} byte cap",
                    self.max_bytes
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
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

    /// A grammatically valid (but NOT self-verifying) CIDv0 fixture.
    const CIDV0: &str = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    /// A grammatically valid CIDv1 dag-pb CID (valid shape, not self-verifying).
    const CIDV1_DAGPB: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    fn tmp(sub: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("citrate-exec-{sub}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// RFC 4648 lowercase base32 (no padding) encode — test-only, to build
    /// self-verifying CIDv1 raw sha2-256 CIDs for fixtures.
    fn base32_lower_encode(bytes: &[u8]) -> String {
        const ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut out = String::new();
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        for &b in bytes {
            acc = (acc << 8) | b as u64;
            nbits += 8;
            while nbits >= 5 {
                nbits -= 5;
                out.push(ALPHA[((acc >> nbits) & 0x1f) as usize] as char);
            }
        }
        if nbits > 0 {
            out.push(ALPHA[((acc << (5 - nbits)) & 0x1f) as usize] as char);
        }
        out
    }

    /// Build the CIDv1 raw sha2-256 CID for `content` (multibase `b`).
    fn cidv1_raw(content: &[u8]) -> String {
        let d = sha256_digest(content);
        let mut raw = vec![0x01, 0x55, 0x12, 0x20];
        raw.extend_from_slice(&d);
        format!("b{}", base32_lower_encode(&raw))
    }

    #[tokio::test]
    async fn provisions_and_caches_with_registry_digest() {
        let dir = tmp("sha-match");
        let content = vec![0xab; 100];
        let src = FakeSource::new(content.clone());
        let m = provision(
            [0x01; 32],
            CIDV0,
            true,
            Some(100),
            Some(sha256_digest(&content)),
            &dir,
            &src,
        )
        .await
        .unwrap();
        assert_eq!(m.bytes_len, 100);
        assert_eq!(m.integrity, Integrity::Sha256Verified);
        assert!(m.path.exists());
        assert_eq!(src.fetch_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // SECREM-01 SVC-2: tampered bytes (right size, wrong content — exactly what
    // a compromised gateway would serve) must be rejected and never cached.
    #[tokio::test]
    async fn tampered_bytes_are_rejected_and_not_cached() {
        let dir = tmp("tampered");
        let good = vec![0xab; 100];
        let mut poisoned = good.clone();
        poisoned[50] ^= 0xff; // same length, different content
        let src = FakeSource::new(poisoned);
        let err = provision(
            [0x07; 32],
            CIDV0,
            true,
            Some(100),
            Some(sha256_digest(&good)),
            &dir,
            &src,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvisionError::DigestMismatch { .. }));
        // Hard failure: nothing usable left on disk.
        assert!(!cache_file(&dir, &[0x07; 32]).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // SECREM-01 SVC-2: a self-verifying CIDv1 raw sha2-256 CID is recomputed
    // locally — no registry digest needed.
    #[tokio::test]
    async fn self_verifying_cid_is_recomputed_locally() {
        let dir = tmp("cid-verify");
        let content = b"genuine model weights".to_vec();
        let src = FakeSource::new(content.clone());
        let m = provision([0x08; 32], &cidv1_raw(&content), true, None, None, &dir, &src)
            .await
            .unwrap();
        assert_eq!(m.integrity, Integrity::CidSha256Verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn self_verifying_cid_rejects_tampered_bytes() {
        let dir = tmp("cid-tampered");
        let content = b"genuine model weights".to_vec();
        let src = FakeSource::new(b"poisoned model weights".to_vec());
        let err = provision([0x09; 32], &cidv1_raw(&content), true, None, None, &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::DigestMismatch { .. }));
        assert!(!cache_file(&dir, &[0x09; 32]).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // SECREM-01 SVC-2: no digest + non-self-verifying CID → fail closed BEFORE
    // any network fetch.
    #[tokio::test]
    async fn unverifiable_cid_fails_closed_without_fetching() {
        let dir = tmp("unverifiable");
        let src = FakeSource::new(vec![0u8; 10]);
        for cid in [CIDV0, CIDV1_DAGPB] {
            let err = provision([0x0a; 32], cid, true, None, None, &dir, &src)
                .await
                .unwrap_err();
            assert!(matches!(err, ProvisionError::Unverifiable { .. }));
        }
        assert_eq!(src.fetch_count(), 0);
    }

    // SECREM-01 SVC-2: a poisoned cache file is discarded and re-fetched, and
    // the replacement is verified.
    #[tokio::test]
    async fn poisoned_cache_is_discarded_and_refetched() {
        let dir = tmp("poisoned-cache");
        let content = vec![0xcd; 64];
        let hash = [0x0b; 32];
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(cache_file(&dir, &hash), vec![0xee; 64]).unwrap(); // same size, wrong bytes
        let src = FakeSource::new(content.clone());
        let m = provision(
            hash,
            CIDV0,
            true,
            Some(64),
            Some(sha256_digest(&content)),
            &dir,
            &src,
        )
        .await
        .unwrap();
        assert_eq!(src.fetch_count(), 1); // cache NOT trusted — re-fetched
        assert_eq!(std::fs::read(&m.path).unwrap(), content);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn size_mismatch_is_rejected() {
        let dir = tmp("size-mismatch");
        let expected = vec![0xab; 100];
        let src = FakeSource::new(vec![0xab; 50]);
        let err = provision(
            [0x02; 32],
            CIDV0,
            true,
            Some(100),
            Some(sha256_digest(&expected)),
            &dir,
            &src,
        )
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
        let err = provision([0x03; 32], "bafycid", false, None, None, &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::Inactive));
        assert_eq!(src.fetch_count(), 0);
    }

    #[tokio::test]
    async fn empty_cid_is_refused() {
        let dir = tmp("empty-cid");
        let src = FakeSource::new(vec![0u8; 10]);
        let err = provision([0x04; 32], "", true, None, None, &dir, &src)
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::EmptyCid));
        assert_eq!(src.fetch_count(), 0);
    }

    #[tokio::test]
    async fn cache_hit_short_circuits_fetch() {
        let dir = tmp("cache-hit");
        let content = vec![0xcd; 64];
        let digest = Some(sha256_digest(&content));
        let src = FakeSource::new(content);
        let hash = [0x05; 32];
        // First call fetches + caches.
        provision(hash, CIDV0, true, Some(64), digest, &dir, &src)
            .await
            .unwrap();
        assert_eq!(src.fetch_count(), 1);
        // Second call for the same model hits the (digest-verified) cache — no new fetch.
        let m2 = provision(hash, CIDV0, true, Some(64), digest, &dir, &src)
            .await
            .unwrap();
        assert_eq!(src.fetch_count(), 1);
        assert_eq!(m2.bytes_len, 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn digest_alone_suffices_without_size() {
        let dir = tmp("no-size");
        let content = vec![0x11; 8];
        let src = FakeSource::new(content.clone());
        let m = provision(
            [0x06; 32],
            CIDV0,
            true,
            None,
            Some(sha256_digest(&content)),
            &dir,
            &src,
        )
        .await
        .unwrap();
        assert_eq!(m.integrity, Integrity::Sha256Verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cid_embedded_sha256_parses_only_v1_raw_sha256() {
        let content = b"abc";
        let cid = cidv1_raw(content);
        assert!(cid.starts_with("bafkrei")); // CIDv1 raw sha2-256 prefix
        assert_eq!(cid_embedded_sha256(&cid), Some(sha256_digest(content)));
        // CIDv0, dag-pb v1, garbage, wrong multibase → not self-verifying.
        assert_eq!(cid_embedded_sha256("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"), None);
        assert_eq!(cid_embedded_sha256("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"), None);
        assert_eq!(cid_embedded_sha256("not a cid"), None);
        assert_eq!(cid_embedded_sha256(""), None);
    }

    // FUA-NODE-AGENT-05: an on-chain `ipfsCID` is attacker-registerable.
    // A malformed / traversal-shaped CID must be rejected *before* any fetch or
    // gateway-URL construction — even when a trusted digest is supplied (the
    // digest protects content integrity, not the URL the daemon is sent to).
    // (RED evidence: failed pre-fix — '../../../api/v0/shutdown' was accepted.)
    #[tokio::test]
    async fn malformed_cid_is_rejected_before_fetch() {
        let dir = tmp("bad-cid");
        let content = vec![0xab; 4];
        let digest = Some(sha256_digest(&content));
        let src = FakeSource::new(content);
        for cid in [
            "../../../api/v0/shutdown",                            // path traversal
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG/../x", // traversal suffix
            "bafkreih?x=1",                                        // query escape
            "bafkreih#frag",                                       // fragment escape
            "..%2F..%2Fapi",                                       // encoded traversal
            "QmTooShort",                                          // too short for CIDv0
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbd0",      // 0 not in base58btc
            "BAFKREIUPPERCASE234",                                 // wrong multibase case
            "ipfs://bafkreih",                                     // scheme smuggling
            "bafybeidagpbnotraw",                                  // non-canonical base32
        ] {
            let res = provision([0x0c; 32], cid, true, None, digest, &dir, &src).await;
            assert!(
                matches!(res, Err(ProvisionError::InvalidCid { .. })),
                "malformed CID {cid:?} was accepted (or mis-classified)"
            );
        }
        assert_eq!(src.fetch_count(), 0, "malformed CID reached the weight source");
    }

    // FUA-NODE-AGENT-05: the gateway source itself must refuse to build a
    // URL from a non-CID identifier (defense in depth below `provision`).
    // (RED evidence: pre-fix the built URL was http://127.0.0.1:1/api/v0/shutdown.)
    #[tokio::test]
    async fn gateway_source_refuses_non_cid_before_url_construction() {
        let src = IpfsGatewaySource::new("http://127.0.0.1:1").unwrap();
        let err = src.fetch("../../api/v0/shutdown").await.unwrap_err();
        assert!(
            matches!(&err, ProvisionError::InvalidCid { .. }),
            "expected a CID-validation rejection, got transport error: {err}"
        );
    }

    // FUA-NODE-AGENT-05: the accept/reject grammar itself.
    #[test]
    fn validate_cid_grammar() {
        // Accepted: bare CIDv0, bare CIDv1 base32lower (dag-pb and raw).
        assert!(validate_cid(CIDV0));
        assert!(validate_cid(CIDV1_DAGPB));
        assert!(validate_cid(&cidv1_raw(b"weights")));
        // Rejected: everything that is not a single bare CID path segment.
        for bad in ["", "Qm", "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdGx", "b", "k51qzi5uqu5dl", "not a cid"] {
            assert!(!validate_cid(bad), "{bad:?} accepted");
        }
    }

    // FUA-NODE-AGENT-06: a plaintext remote gateway is refused at construction;
    // the loopback local-Kubo posture and https remotes remain fine.
    #[test]
    fn gateway_source_refuses_plaintext_remote_gateway() {
        assert!(IpfsGatewaySource::new("http://203.0.113.7:8080").is_err());
        assert!(IpfsGatewaySource::new("http://127.0.0.1:8080").is_ok());
        assert!(IpfsGatewaySource::new("https://ipfs.example").is_ok());
    }

    #[test]
    fn base32_roundtrip() {
        for len in [0usize, 1, 4, 5, 31, 32, 36, 100] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            let enc = base32_lower_encode(&data);
            assert_eq!(base32_lower_decode(&enc), Some(data), "len {len}");
        }
        assert_eq!(base32_lower_decode("UPPER"), None);
        assert_eq!(base32_lower_decode("01"), None); // 0,1 not in alphabet
    }
}
