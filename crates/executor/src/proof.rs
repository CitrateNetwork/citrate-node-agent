//! `proof` — the Commitment-tier proof builder.
//!
//! Produces the exact bytes `ComputeVerifier._verifyCommitment` accepts on-chain.
//!
//! ## The commitment formula is `keccak256(output ‖ nonce)` — NOT what the docs say
//!
//! `ComputeVerifier.sol` has a **comment/code mismatch** worth knowing:
//! - The `VerificationRecord.commitmentHash` field is *documented* (struct comment,
//!   line 36) as `SHA3(input || output || nonce)`.
//! - The **executable** predicate (`verify`, lines 280–281; `_verifyCommitment`,
//!   lines 527–532) is `keccak256(abi.encodePacked(output, nonce)) == commitment`.
//!
//! The code wins. The commitment a provider must submit is
//! `keccak256(output ‖ nonce)`; the input is **not** bound into it. So the
//! Commitment tier proves "I committed to this output before revealing it,"
//! **not** "I ran the right model on the right input" — that stronger property is
//! the ZK/TEE tiers' job. Building the commitment the *documented* way would make
//! `_verifyCommitment` reject it and the job would never complete. We build to the
//! code. (Logged as a finding for the chain team — see SELL handoff / TECH_DEBT.)
//!
//! ## Byte layout
//! - `commitment = keccak256(output ‖ nonce)` — recorded by `submitCommitment(jobId, commitment)`.
//! - `proofData  = commitment(32) ‖ nonce(32) ‖ output` — the `proof` arg of
//!   `submitResult`, sliced back apart by `_verifyCommitment` (`proofData[:32]`,
//!   `[32:64]`, `[64:]`).
//! - `outputHash = keccak256(output)` — the `submitResult` `outputHash` arg
//!   (used for the marketplace's `ResultSubmitted` event; the verifier uses
//!   `proofData`, not this).

use lifecycle::CommitmentArtifacts;
use tiny_keccak::{Hasher, Keccak};

/// `keccak256` of the concatenation of `parts`.
fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// Abstracts building a verification proof from an inference output, so the
/// daemon is proof-tier-agnostic. Only the Commitment tier ships in SELL-S2
/// (the bidder caps bids < 10 SALT so jobs never auto-upgrade off Commitment);
/// ZK/TEE makers land later behind the same trait.
pub trait ProofMaker {
    /// Build the on-chain artifacts for `output` under `nonce`. `nonce` must be
    /// the **same** value across the commitment and result steps for one job.
    fn build(&self, output: &[u8], nonce: [u8; 32]) -> CommitmentArtifacts;
}

/// The Commitment-tier prover: pure keccak, no PIN, no ZK.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommitmentProver;

impl CommitmentProver {
    pub fn new() -> Self {
        Self
    }

    /// `commitment = keccak256(output ‖ nonce)` — the value `_verifyCommitment`
    /// recomputes and compares against the stored `commitmentHash`.
    pub fn commitment(output: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
        keccak256(&[output, nonce])
    }

    /// `outputHash = keccak256(output)` — the `submitResult` `outputHash` arg.
    pub fn output_hash(output: &[u8]) -> [u8; 32] {
        keccak256(&[output])
    }

    /// `proofData = commitment(32) ‖ nonce(32) ‖ output`.
    pub fn proof_data(commitment: &[u8; 32], nonce: &[u8; 32], output: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(64 + output.len());
        p.extend_from_slice(commitment);
        p.extend_from_slice(nonce);
        p.extend_from_slice(output);
        p
    }
}

impl ProofMaker for CommitmentProver {
    fn build(&self, output: &[u8], nonce: [u8; 32]) -> CommitmentArtifacts {
        let commitment = Self::commitment(output, &nonce);
        CommitmentArtifacts {
            commitment,
            output_hash: Self::output_hash(output),
            proof: Self::proof_data(&commitment, &nonce, output),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-implement the EXACT on-chain `_verifyCommitment` predicate in Rust, so
    /// "the contract would accept this proof" is asserted offline. If this ever
    /// fails, our proof bytes would be rejected on-chain. (Solidity:
    /// `commitment == rec.commitmentHash && keccak256(output‖nonce) == commitment`.)
    fn on_chain_verify(stored_commitment: &[u8; 32], proof_data: &[u8]) -> bool {
        if proof_data.len() < 64 {
            return false;
        }
        let commitment = &proof_data[0..32];
        let nonce = &proof_data[32..64];
        let output = &proof_data[64..];
        if commitment != stored_commitment {
            return false;
        }
        let recomputed = keccak256(&[output, nonce]);
        recomputed.as_slice() == commitment
    }

    #[test]
    fn proof_satisfies_the_on_chain_predicate() {
        let output = b"the model said hello";
        let nonce = [0x7u8; 32];
        let art = CommitmentProver.build(output, nonce);

        // The commitment the agent submits via submitCommitment.
        let stored = art.commitment;
        // _verifyCommitment(stored, proofData) must return Valid.
        assert!(on_chain_verify(&stored, &art.proof));
    }

    #[test]
    fn commitment_is_keccak_output_then_nonce_not_input() {
        let output = b"out";
        let nonce = [0x1u8; 32];
        let c = CommitmentProver::commitment(output, &nonce);
        // Exactly keccak256(output ‖ nonce).
        assert_eq!(c, keccak256(&[output.as_slice(), &nonce]));
        // And NOT keccak256(input ‖ output ‖ nonce) — prove the docs' formula
        // would have produced a different (rejected) commitment.
        let input = b"some input";
        let documented = keccak256(&[input.as_slice(), output, &nonce]);
        assert_ne!(c, documented);
    }

    #[test]
    fn proof_data_layout_is_commitment_nonce_output() {
        let output = b"hello world";
        let nonce = [0x9u8; 32];
        let art = CommitmentProver.build(output, nonce);
        assert_eq!(art.proof.len(), 64 + output.len());
        assert_eq!(&art.proof[0..32], &art.commitment);
        assert_eq!(&art.proof[32..64], &nonce);
        assert_eq!(&art.proof[64..], output);
    }

    #[test]
    fn output_hash_is_keccak_of_output() {
        let output = b"result bytes";
        let art = CommitmentProver.build(output, [0u8; 32]);
        assert_eq!(art.output_hash, keccak256(&[output.as_slice()]));
    }

    #[test]
    fn wrong_nonce_in_proof_is_rejected_by_predicate() {
        let output = b"abc";
        let good_nonce = [0x1u8; 32];
        let art = CommitmentProver.build(output, good_nonce);
        // Tamper the nonce inside proofData but keep the (now-stale) commitment.
        let mut tampered = art.proof.clone();
        tampered[32..64].copy_from_slice(&[0x2u8; 32]);
        assert!(!on_chain_verify(&art.commitment, &tampered));
    }

    #[test]
    fn tampered_output_is_rejected_by_predicate() {
        let output = b"original";
        let nonce = [0x5u8; 32];
        let art = CommitmentProver.build(output, nonce);
        let mut tampered = art.proof.clone();
        // Flip a byte of the revealed output → keccak(output‖nonce) ≠ commitment.
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(!on_chain_verify(&art.commitment, &tampered));
    }
}
