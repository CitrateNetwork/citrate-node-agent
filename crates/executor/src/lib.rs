//! `executor` — the SELL-S2 job-execution backend.
//!
//! Three steps the daemon composes for a won Commitment-tier job:
//! 1. [`models`] — provision the weights (`CID → fetch → integrity-check → cache`).
//! 2. [`runtime`] — run inference behind the [`runtime::Inference`] trait.
//! 3. [`proof`] — build the Commitment proof bytes the on-chain
//!    `ComputeVerifier._verifyCommitment` predicate accepts, as a
//!    [`lifecycle::CommitmentArtifacts`] the lifecycle driver submits.
//!
//! Everything network/inference sits behind a trait so the logic is unit-tested
//! fully offline; live paths gate on `CITRATE_*` env. No keys (ADR-agent-signing).

pub mod models;
pub mod proof;
pub mod runtime;

pub use lifecycle::CommitmentArtifacts;
pub use models::{
    provision, sha256_digest, Integrity, IpfsGatewaySource, ProvisionError, ProvisionedModel,
    WeightSource,
};
pub use proof::{keccak256_bytes, CommitmentProver, ProofMaker};
pub use runtime::{
    Inference, InferenceError, InferenceOutput, LlamaServerInference, LLAMA_FIXED_SEED,
};
