//! `sidecar` — the production [`Sealer`]: drives the `citrate-sealer` binary
//! (citrate-chain, PIN-S6) out-of-process over its line-delimited JSON protocol.
//!
//! The daemon never links the halo2 prover; it spawns the sidecar per call,
//! writes one request line, reads one response line. The sidecar re-seals
//! deterministically for PoSt, so no cross-call state crosses the boundary.
//!
//! Wire (must match `citrate-chain` `bin/citrate-sealer`):
//! ```json
//! {"op":"seal","pinner":"0x..","cid":"0x..","sector":"0x..","epoch":"0x..","data":["0x..",x4],"challenge_index":0}
//! {"op":"prove_post", … ,"challenge_index":<nonce>}
//! ```
//! Response: `{"ok":true,"replica_id","comm_d","comm_r","comm_c","proof"}` (seal)
//! / `{"ok":true,"proof"}` (post) / `{"ok":false,"error"}`.

use crate::{SealArtifacts, SealInputs, Sealer, SealerError};

/// A [`Sealer`] backed by the out-of-process `citrate-sealer` binary.
#[derive(Debug, Clone)]
pub struct SidecarSealer {
    /// Path to the `citrate-sealer` executable (from config /
    /// `CITRATE_SEALER_BIN`). The daemon refuses to construct one if the binary
    /// is absent — per the no-stub rule, no fake fallback.
    bin: std::path::PathBuf,
    /// PBA-L6b-039: wall-clock budget for one sidecar call. A wedged prover
    /// must error (and be killed), never park the pinning tick past the
    /// challenge window. `CITRATE_SEALER_TIMEOUT_SECS`, default
    /// [`DEFAULT_SEALER_TIMEOUT_SECS`].
    timeout: std::time::Duration,
}

/// Default per-call sidecar budget (seconds). Sealing/proving is CPU-heavy, so
/// the default is generous; it only has to be finite.
pub const DEFAULT_SEALER_TIMEOUT_SECS: u64 = 900;

fn sealer_timeout_from_env() -> std::time::Duration {
    let secs = std::env::var("CITRATE_SEALER_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_SEALER_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

impl SidecarSealer {
    /// Construct against a sealer binary, verifying it exists (fail-closed: a
    /// missing prover means the node cannot seal, not a silent no-op).
    pub fn new(bin: impl Into<std::path::PathBuf>) -> Result<Self, SealerError> {
        let bin = bin.into();
        if !bin.exists() {
            return Err(SealerError::Prove(format!(
                "citrate-sealer binary not found at {}",
                bin.display()
            )));
        }
        Ok(Self {
            bin,
            timeout: sealer_timeout_from_env(),
        })
    }

    /// Override the per-call budget.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Construct from `CITRATE_SEALER_BIN` (the deployment's configured path).
    pub fn from_env() -> Result<Self, SealerError> {
        let p = std::env::var("CITRATE_SEALER_BIN")
            .map_err(|_| SealerError::Prove("CITRATE_SEALER_BIN not set".into()))?;
        Self::new(p)
    }

    /// Spawn the sidecar, send `request_json`, return the parsed response object.
    async fn call(&self, request_json: String) -> Result<serde_json::Value, SealerError> {
        use tokio::io::AsyncWriteExt as _;
        use tokio::process::Command;

        let mut child = Command::new(&self.bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // PBA-L6b-039: a timed-out call drops the child → it is killed.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SealerError::Prove(format!("spawn citrate-sealer: {e}")))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| SealerError::Prove("no sidecar stdin".into()))?;
            stdin
                .write_all(format!("{request_json}\n").as_bytes())
                .await
                .map_err(|e| SealerError::Prove(format!("write to sidecar: {e}")))?;
            // Drop stdin → EOF → the sidecar's read loop responds and exits.
        }

        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                SealerError::Prove(format!(
                    "citrate-sealer did not answer within {:?}; killed (PBA-L6b-039)",
                    self.timeout
                ))
            })?
            .map_err(|e| SealerError::Prove(format!("sidecar wait: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(SealerError::Prove(format!(
                "sidecar exited {}: {err}",
                out.status
            )));
        }
        let line = String::from_utf8_lossy(&out.stdout);
        let first = line
            .lines()
            .next()
            .ok_or_else(|| SealerError::Prove("empty sidecar response".into()))?;
        let val: serde_json::Value = serde_json::from_str(first)
            .map_err(|e| SealerError::Prove(format!("bad sidecar json: {e}")))?;
        if val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let msg = val
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown sidecar error");
            return Err(SealerError::Prove(format!("sidecar: {msg}")));
        }
        Ok(val)
    }
}

fn be_hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn u128_be_hex32(v: u128) -> String {
    let mut b = [0u8; 32];
    b[16..32].copy_from_slice(&v.to_be_bytes());
    be_hex32(&b)
}

fn request_json(op: &str, inputs: &SealInputs, challenge_index: u64) -> String {
    let data: Vec<String> = inputs.data.iter().map(be_hex32).collect();
    serde_json::json!({
        "op": op,
        "pinner": be_hex32(&inputs.pinner_identity),
        "cid": be_hex32(&inputs.cid),
        "sector": u128_be_hex32(inputs.sector),
        "epoch": u128_be_hex32(inputs.epoch),
        "data": data,
        "challenge_index": challenge_index,
    })
    .to_string()
}

fn field_bytes32(v: &serde_json::Value, key: &str) -> Result<[u8; 32], SealerError> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| SealerError::Prove(format!("sidecar missing {key}")))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| SealerError::Prove(format!("bad {key} hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| SealerError::Prove(format!("{key} not 32 bytes")))
}

fn field_proof(v: &serde_json::Value) -> Result<Vec<u8>, SealerError> {
    let s = v
        .get("proof")
        .and_then(|x| x.as_str())
        .ok_or_else(|| SealerError::Prove("sidecar missing proof".into()))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| SealerError::Prove(format!("bad proof hex: {e}")))
}

impl Sealer for SidecarSealer {
    async fn seal(&self, inputs: &SealInputs) -> Result<SealArtifacts, SealerError> {
        // Seal-time PoRep proof is at index 0 (the contract's sealCommit wire
        // uses challengeNonce=0).
        let v = self.call(request_json("seal", inputs, 0)).await?;
        Ok(SealArtifacts {
            replica_id: field_bytes32(&v, "replica_id")?,
            comm_d: field_bytes32(&v, "comm_d")?,
            comm_r: field_bytes32(&v, "comm_r")?,
            comm_c: field_bytes32(&v, "comm_c")?,
            porep_proof: field_proof(&v)?,
        })
    }

    async fn prove_post(
        &self,
        inputs: &SealInputs,
        challenge_index: u64,
    ) -> Result<Vec<u8>, SealerError> {
        let v = self
            .call(request_json("prove_post", inputs, challenge_index))
            .await?;
        field_proof(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PBA-L6b-039: a sidecar that never answers must time out (and be
    // killed), not park the pinning tick forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn l6b_039_wedged_sidecar_times_out() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("l6b039-sealer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("citrate-sealer");
        std::fs::write(&bin, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sealer = SidecarSealer::new(&bin)
            .unwrap()
            .with_timeout(std::time::Duration::from_secs(1));
        let inputs = SealInputs {
            pinner_identity: [0xBE; 32],
            cid: [0x11; 32],
            sector: 7,
            epoch: 42,
            data: [[0u8; 32]; 4],
        };
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(std::time::Duration::from_secs(10), sealer.seal(&inputs))
            .await
            .expect("PBA-L6b-039: sidecar call never returned (no timeout)");
        assert!(r.is_err(), "a wedged sidecar must error");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_binary_fails_closed() {
        let r = SidecarSealer::new("/nonexistent/citrate-sealer");
        assert!(matches!(r, Err(SealerError::Prove(_))));
    }

    #[test]
    fn request_json_shape() {
        let inputs = SealInputs {
            pinner_identity: [0xBE; 32],
            cid: [0x11; 32],
            sector: 7,
            epoch: 42,
            data: [[0u8; 32]; 4],
        };
        let j: serde_json::Value =
            serde_json::from_str(&request_json("seal", &inputs, 0)).expect("json");
        assert_eq!(j["op"], "seal");
        assert_eq!(j["pinner"], format!("0x{}", "be".repeat(32)));
        assert_eq!(j["sector"].as_str().unwrap().len(), 66); // 0x + 64
        assert_eq!(j["data"].as_array().unwrap().len(), 4);
        assert_eq!(j["challenge_index"], 0);
    }

    #[test]
    fn u128_hex_is_left_padded_be() {
        // 7 -> ...0007 in the low 16 bytes.
        let h = u128_be_hex32(7);
        assert!(h.ends_with("00000007"));
        assert_eq!(h.len(), 66);
    }

    /// Full process e2e against the REAL citrate-sealer binary, gated on
    /// CITRATE_SEALER_BIN (mirrors chainio's CITRATE_RPC_URL live-test posture).
    #[tokio::test]
    async fn live_sidecar_seal_roundtrip() {
        let bin = match std::env::var("CITRATE_SEALER_BIN") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("CITRATE_SEALER_BIN not set; skipping live sidecar test");
                return;
            }
        };
        let sealer = SidecarSealer::new(bin).expect("sealer");
        let inputs = SealInputs {
            pinner_identity: {
                let mut b = [0u8; 32];
                b[31] = 0x05; // small canonical field element
                b
            },
            cid: {
                let mut b = [0u8; 32];
                b[31] = 0x09;
                b
            },
            sector: 7,
            epoch: 42,
            data: [
                { let mut b = [0u8; 32]; b[30] = 0x03; b },
                { let mut b = [0u8; 32]; b[30] = 0x07; b },
                { let mut b = [0u8; 32]; b[30] = 0x0b; b },
                { let mut b = [0u8; 32]; b[30] = 0x0f; b },
            ],
        };
        let sealed = sealer.seal(&inputs).await.expect("seal");
        assert!(!sealed.porep_proof.is_empty(), "real proof bytes returned");
        assert_ne!(sealed.replica_id, [0u8; 32]);
        let post = sealer.prove_post(&inputs, 1).await.expect("prove_post");
        assert!(!post.is_empty());
    }
}
