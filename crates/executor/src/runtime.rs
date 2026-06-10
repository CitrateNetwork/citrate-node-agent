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
}

impl core::fmt::Display for InferenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InferenceError::Backend(m) => write!(f, "inference backend error: {m}"),
            InferenceError::ModelMissing => write!(f, "provisioned model file is missing"),
        }
    }
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

/// Resident llama.cpp (`llama-server`) adapter — POSTs `{base_url}/completion`.
pub struct LlamaServerInference {
    base_url: String,
    client: reqwest::Client,
}

impl LlamaServerInference {
    /// `base_url` is the resident server, e.g. `http://127.0.0.1:8080`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
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
        let prompt = String::from_utf8_lossy(input).into_owned();
        let body = serde_json::json!({ "prompt": prompt, "n_predict": 512 });
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
        let v: serde_json::Value = resp
            .json()
            .await
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
        let engine = LlamaServerInference::new("http://127.0.0.1:1"); // unused — file check first
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
        let engine = LlamaServerInference::new(url);
        let out = engine.run(&model, b"Say hello in one word.").await.unwrap();
        assert!(!out.bytes.is_empty());
    }
}
