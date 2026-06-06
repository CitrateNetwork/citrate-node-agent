//! `verifier` — the one `ComputeVerifier` read the relay needs: has the
//! commitment for a job been recorded on-chain yet?
//!
//! This is the chain-truth that gates `submitResult`: the verifier requires
//! `commitmentSubmitted == true` (INV-3/INV-7) before a result reveal is
//! accepted. Deriving "committed" from chain — rather than optimistic local
//! state — keeps the daemon correct under an asynchronous signing relay
//! (`submitResult` can never race ahead of `submitCommitment` landing).
//!
//! `getRecord(uint256) -> VerificationRecord` returns an all-static struct, so
//! the members are a flat sequence of 32-byte words. `commitmentSubmitted` is
//! word index 5: `jobId(0) jobValue(1) tier(2) result(3) commitmentHash(4)
//! commitmentSubmitted(5) …`.

use crate::abi::{AbiError, Decoder};
use crate::selectors;

/// `getRecord(uint256 jobId)` calldata.
pub fn encode_get_record(job_id: u128) -> Vec<u8> {
    crate::abi::encode_call(selectors::get_record(), &[crate::abi::word_from_u128(job_id)])
}

/// Decode `commitmentSubmitted` (word 5) from a `getRecord` return.
pub fn decode_commitment_submitted(data: &[u8]) -> Result<bool, AbiError> {
    let mut d = Decoder::new(data);
    for _ in 0..5 {
        d.word()?; // skip jobId, jobValue, tier, result, commitmentHash
    }
    d.bool()
}

/// Live-RPC helper (gated by `CITRATE_RPC_URL` in tests).
pub mod live {
    use super::*;
    use crate::abi::Address;
    use crate::rpc::{RpcClient, RpcError};

    /// Read whether a job's commitment has been recorded on-chain.
    pub async fn commitment_submitted(
        client: &RpcClient,
        verifier: Address,
        job_id: u128,
    ) -> Result<bool, RpcError> {
        let data = client
            .eth_call(verifier, &encode_get_record(job_id))
            .await?;
        Ok(decode_commitment_submitted(&data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::word_from_u128;

    /// Build a synthetic `getRecord` return (11 static words) with a given
    /// `commitmentSubmitted` flag at word 5.
    fn synth_record(committed: bool) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&word_from_u128(7)); // 0: jobId
        d.extend_from_slice(&word_from_u128(4 * 10u128.pow(18))); // 1: jobValue
        d.extend_from_slice(&word_from_u128(0)); // 2: tier = Commitment
        d.extend_from_slice(&word_from_u128(0)); // 3: result = Pending
        d.extend_from_slice(&[0u8; 32]); // 4: commitmentHash
        d.extend_from_slice(&word_from_u128(committed as u128)); // 5: commitmentSubmitted
        for _ in 0..5 {
            d.extend_from_slice(&[0u8; 32]); // 6..10: remaining static fields
        }
        d
    }

    #[test]
    fn decodes_commitment_submitted_true_and_false() {
        assert!(decode_commitment_submitted(&synth_record(true)).unwrap());
        assert!(!decode_commitment_submitted(&synth_record(false)).unwrap());
    }

    #[test]
    fn encodes_get_record_calldata() {
        let call = encode_get_record(7);
        assert_eq!(call.len(), 36);
        assert_eq!(&call[0..4], &selectors::get_record());
        assert_eq!(call[4 + 31], 7);
    }

    #[test]
    fn truncated_record_errors() {
        assert!(decode_commitment_submitted(&[0u8; 96]).is_err());
    }
}
