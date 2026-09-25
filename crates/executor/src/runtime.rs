//! `runtime` — the inference adapter seam (ADR-inference-runtime).
//!
//! The marketplace pays a provider to *run a model on an input and return the
//! output*. The inference-gateway only **routes**; compute-pool's worker is
//! training-only — so this is a **net-new execution backend** (planset risk R4).
//! The runtime is abstracted behind [`Inference`] so the daemon is engine-agnostic:
//! SELL-S2 ships one adapter ([`LlamaServerInference`], a *resident* llama.cpp
//! server — chosen because cold-load is the known risk), and candle / vLLM
//! adapters land additively behind the same trait.
//!
//! The adapter targets a server **pre-loaded with the model** (that is the whole
//! point of a resident server — no per-job cold-load). Binding the running
//! server to the [`ProvisionedModel`] we verified is operator configuration for
//! single-model nodes today; multi-model routing is a follow-up (tech-debt).

use crate::models::ProvisionedModel;

/// The bytes a model produced for an input. These are what the Commitment proof
/// commits to (`keccak256(output ‖ nonce)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceOutput {
    pub bytes: Vec<u8>,
}

/// Why inference failed.
#[derive(Debug)]
pub enum InferenceError {
    /// The backend (llama-server, etc.) errored or was unreachable.
    Backend(String),
    /// The provisioned model file is missing from disk.
    ModelMissing,
    /// NA-B-005: the resident backend is bound to a different model than the one
    /// the job provisioned + verified. Running would serve model `got` while the
    /// buyer settled for `expected`, and the Commitment (which binds only
    /// `(output, nonce)`, not the model) would be accepted anyway. Fail closed.
    ModelMismatch {
        /// The `modelHash` the resident backend was declared to serve.
        expected: [u8; 32],
        /// The `modelHash` this job provisioned + verified.
        got: [u8; 32],
    },
}

impl core::fmt::Display for InferenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InferenceError::Backend(m) => write!(f, "inference backend error: {m}"),
            InferenceError::ModelMissing => write!(f, "provisioned model file is missing"),
            InferenceError::ModelMismatch { expected, got } => write!(
                f,
                "resident-model mismatch: backend serves {} but job provisioned {}",
                hex32(expected),
                hex32(got)
            ),
        }
    }
}

/// Lowercase hex of a 32-byte model hash (for error surfaces).
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    s
}

impl std::error::Error for InferenceError {}

/// Abstracts running one inference. Async (the backend is a server / GPU) behind
/// the trait so the daemon + lifecycle tests drive a deterministic fake offline.
pub trait Inference {
    /// Run `model` on `input`, returning the raw output bytes.
    fn run(
        &self,
        model: &ProvisionedModel,
        input: &[u8],
    ) -> impl std::future::Future<Output = Result<InferenceOutput, InferenceError>> + Send;
}

/// PBA-L6b-007: the fixed sampling seed sent with every completion. Together
/// with `temperature: 0` (greedy decoding) it makes a re-run reproduce the same
/// output, so a restart can never reveal an output the commitment did not bind.
pub const LLAMA_FIXED_SEED: u32 = 40204;

/// Resident llama.cpp (`llama-server`) adapter — POSTs `{base_url}/completion`.
pub struct LlamaServerInference {
    base_url: String,
    client: reqwest::Client,
    /// NA-B-005: the `modelHash` this resident backend is declared to serve, if
    /// the operator bound it (`CITRATE_RESIDENT_MODEL_HASH`). When set, `run`
    /// refuses any job whose provisioned model differs — the resident server is
    /// started independently of provisioning, so without this binding a
    /// multi-model / misconfigured node would faithfully verify model A and then
    /// serve whatever model B the backend happens to hold. `None` preserves the
    /// prior best-effort behavior (single-model nodes that have not declared it).
    resident_model_hash: Option<[u8; 32]>,
}

impl LlamaServerInference {
    /// `base_url` is the resident server, e.g. `http://127.0.0.1:8080`.
    ///
    /// FUA-NODE-AGENT-06 (SECREM-02 WP 7.4): the endpoint is validated by
    /// [`chainio::outbound::validate_outbound_url`] — plaintext `http://` is
    /// only accepted for loopback (the resident-server posture above); a
    /// remote inference endpoint must be `https://`. Job inputs/outputs cross
    /// this link and the output feeds the commitment proof, so fail closed at
    /// construction.
    pub fn new(base_url: impl Into<String>) -> Result<Self, chainio::outbound::OutboundUrlError> {
        Self::build(base_url, None)
    }

    /// Like [`Self::new`], but binds the adapter to the `modelHash` the resident
    /// backend serves (NA-B-005). `run` then refuses any job whose provisioned +
    /// verified model differs, closing the settle-vs-serve gap where a node
    /// serves a different model than the one the buyer paid for.
    pub fn with_resident_model(
        base_url: impl Into<String>,
        resident_model_hash: [u8; 32],
    ) -> Result<Self, chainio::outbound::OutboundUrlError> {
        Self::build(base_url, Some(resident_model_hash))
    }

    fn build(
        base_url: impl Into<String>,
        resident_model_hash: Option<[u8; 32]>,
    ) -> Result<Self, chainio::outbound::OutboundUrlError> {
        let base_url = base_url.into();
        chainio::outbound::validate_outbound_url(&base_url)?;
        Ok(Self {
            base_url,
            // NA-B-001/003: a timeout-configured client — a stalled inference
            // backend must error, never park `run()` past the job's execution
            // deadline (the on-chain timeout slash).
            client: chainio::outbound::timed_http_client(),
            resident_model_hash,
        })
    }
}

impl Inference for LlamaServerInference {
    async fn run(
        &self,
        model: &ProvisionedModel,
        input: &[u8],
    ) -> Result<InferenceOutput, InferenceError> {
        // The resident server holds the weights; we still require the verified
        // file to exist (it is the provisioning contract / audit anchor).
        if !model.path.exists() {
            return Err(InferenceError::ModelMissing);
        }
        // NA-B-005: if the operator declared which model this backend serves,
        // refuse a job for any other model rather than serving the wrong weights
        // under a Commitment that would still be accepted on-chain.
        if let Some(expected) = self.resident_model_hash {
            if expected != model.model_hash {
                return Err(InferenceError::ModelMismatch {
                    expected,
                    got: model.model_hash,
                });
            }
        }
        let prompt = String::from_utf8_lossy(input).into_owned();
        // PBA-L6b-007: greedy decoding + a fixed seed, so the output is
        // reproducible and a post-restart re-run can never diverge from the
        // committed output.
        let body = serde_json::json!({
            "prompt": prompt,
            "n_predict": 512,
            "temperature": 0.0,
            "seed": LLAMA_FIXED_SEED,
        });
        let url = format!("{}/completion", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| InferenceError::Backend(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(InferenceError::Backend(format!("server status {}", resp.status())));
        }
        // PBA-L6b-024: capped body read (redirects refused by the client and
        // again here), never an unbounded `Response::json`.
        let body = chainio::outbound::read_body_capped(resp, chainio::outbound::max_response_bytes())
            .await
            .map_err(|e| InferenceError::Backend(e.to_string()))?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| InferenceError::Backend(e.to_string()))?;
        let content = v
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| InferenceError::Backend("response had no `content` field".into()))?;
        Ok(InferenceOutput {
            bytes: content.as_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Integrity;
    use std::path::PathBuf;

    fn fake_model() -> (ProvisionedModel, PathBuf) {
        // A real on-disk file so `path.exists()` holds for adapters that check it.
        let dir = std::env::temp_dir().join("citrate-exec-runtime");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("model.bin");
        std::fs::write(&path, b"weights").unwrap();
        (
            ProvisionedModel {
                model_hash: [0x01; 32],
                path: path.clone(),
                bytes_len: 7,
                integrity: Integrity::Sha256Verified,
            },
            path,
        )
    }

    /// Deterministic fake engine: echoes the input with a fixed prefix. Used by
    /// the lifecycle/daemon tests so the whole execute→prove path is exercised
    /// without a GPU.
    struct EchoInference;
    impl Inference for EchoInference {
        async fn run(
            &self,
            _model: &ProvisionedModel,
            input: &[u8],
        ) -> Result<InferenceOutput, InferenceError> {
            let mut bytes = b"echo:".to_vec();
            bytes.extend_from_slice(input);
            Ok(InferenceOutput { bytes })
        }
    }

    #[tokio::test]
    async fn fake_inference_is_deterministic() {
        let (model, _p) = fake_model();
        let out = EchoInference.run(&model, b"prompt").await.unwrap();
        assert_eq!(out.bytes, b"echo:prompt");
        // Deterministic: same input → same output (load-bearing for the
        // commit→reveal proof to verify).
        let out2 = EchoInference.run(&model, b"prompt").await.unwrap();
        assert_eq!(out, out2);
    }

    #[tokio::test]
    async fn llama_adapter_errors_when_model_file_missing() {
        let model = ProvisionedModel {
            model_hash: [0x09; 32],
            path: PathBuf::from("/nonexistent/citrate/model.bin"),
            bytes_len: 0,
            integrity: Integrity::Sha256Verified,
        };
        let engine =
            LlamaServerInference::new("http://127.0.0.1:1").unwrap(); // unused — file check first
        let err = engine.run(&model, b"x").await.unwrap_err();
        assert!(matches!(err, InferenceError::ModelMissing));
    }

    /// Live smoke test against a real resident llama-server. Skips cleanly unless
    /// `CITRATE_LLAMA_URL` is set (mirrors the `CITRATE_RPC_URL` live-test posture).
    #[tokio::test]
    async fn live_llama_server_completes_when_configured() {
        let Ok(url) = std::env::var("CITRATE_LLAMA_URL") else {
            return; // not configured → skip
        };
        let (model, _p) = fake_model();
        let engine = LlamaServerInference::new(url)
            .expect("CITRATE_LLAMA_URL must be https:// or loopback http://");
        let out = engine.run(&model, b"Say hello in one word.").await.unwrap();
        assert!(!out.bytes.is_empty());
    }

    // NA-B-005: a backend bound to model A must refuse a job that provisioned a
    // different model B, before it ever POSTs the prompt — otherwise it would
    // serve B under a Commitment the buyer settled for A.
    #[tokio::test]
    async fn llama_adapter_refuses_a_job_for_a_different_resident_model() {
        let (mut model, _p) = fake_model(); // model_hash = [0x01; 32]
        let resident = [0x01u8; 32];
        let other = [0xABu8; 32];

        // Bound to the resident model, a matching job passes the binding check
        // (it then fails only at the network POST, which is fine — the point is
        // the binding did not reject it). A mismatching job is refused up front.
        let engine = LlamaServerInference::with_resident_model("http://127.0.0.1:1", resident).unwrap();

        model.model_hash = other;
        let err = engine.run(&model, b"x").await.unwrap_err();
        assert!(
            matches!(err, InferenceError::ModelMismatch { expected, got } if expected == resident && got == other),
            "must refuse a job for a model the resident backend does not serve, got {err:?}"
        );

        // The unbound adapter (no declared resident model) keeps the prior
        // best-effort behavior: it does not reject on model identity.
        let unbound = LlamaServerInference::new("http://127.0.0.1:1").unwrap();
        let err2 = unbound.run(&model, b"x").await.unwrap_err();
        assert!(
            !matches!(err2, InferenceError::ModelMismatch { .. }),
            "an unbound adapter must not raise a model mismatch"
        );
    }

    // FUA-NODE-AGENT-06: a plaintext remote inference endpoint is refused at
    // construction; loopback http and https remote remain fine.
    #[test]
    fn llama_adapter_refuses_plaintext_remote_endpoint() {
        assert!(LlamaServerInference::new("http://203.0.113.7:8080").is_err());
        assert!(LlamaServerInference::new("http://127.0.0.1:8080").is_ok());
        assert!(LlamaServerInference::new("https://inference.example:8080").is_ok());
    }
}
