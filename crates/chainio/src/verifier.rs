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

/// Decode the verification `tier` (word 2) from a `getRecord` return: the
/// tier the job is actually verified under (a Commitment request above
/// `VALUE_THRESHOLD` reads ZKProof here).
pub fn decode_record_tier(data: &[u8]) -> Result<crate::marketplace::VerificationTier, AbiError> {
    let mut d = Decoder::new(data);
    d.word()?; // jobId
    d.word()?; // jobValue
    crate::marketplace::VerificationTier::from_u8(d.u8_enum()?)
}

/// `commitmentBlock(uint256 jobId)` calldata.
pub fn encode_commitment_block(job_id: u128) -> Vec<u8> {
    crate::abi::encode_call(
        selectors::commitment_block(),
        &[crate::abi::word_from_u128(job_id)],
    )
}

/// Decode a single `uint256` return that must fit a block height.
pub fn decode_block(data: &[u8]) -> Result<u128, AbiError> {
    Decoder::new(data).u128()
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

    /// Read the job's effective verification tier (`getRecord(jobId).tier`).
    pub async fn record_tier(
        client: &RpcClient,
        verifier: Address,
        job_id: u128,
    ) -> Result<crate::marketplace::VerificationTier, RpcError> {
        let data = client
            .eth_call(verifier, &encode_get_record(job_id))
            .await?;
        Ok(decode_record_tier(&data)?)
    }

    /// Read `commitmentBlock(jobId)` — block the commitment landed in.
    pub async fn commitment_block(
        client: &RpcClient,
        verifier: Address,
        job_id: u128,
    ) -> Result<u128, RpcError> {
        let data = client
            .eth_call(verifier, &encode_commitment_block(job_id))
            .await?;
        Ok(decode_block(&data)?)
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
    fn decodes_effective_tier_word_2() {
        use crate::marketplace::VerificationTier;
        let mut r = synth_record(true);
        assert_eq!(
            decode_record_tier(&r).unwrap(),
            VerificationTier::Commitment
        );
        r[2 * 32 + 31] = 1;
        assert_eq!(decode_record_tier(&r).unwrap(), VerificationTier::ZKProof);
        r[2 * 32 + 31] = 3;
        assert!(decode_record_tier(&r).is_err());
    }

    #[test]
    fn encodes_commitment_block_and_decodes_height() {
        let call = encode_commitment_block(9);
        assert_eq!(&call[0..4], &selectors::commitment_block());
        assert_eq!(call[35], 9);
        assert_eq!(decode_block(&word_from_u128(181)).unwrap(), 181);
        assert!(decode_block(&[0u8; 8]).is_err());
    }

    #[test]
    fn truncated_record_errors() {
        assert!(decode_commitment_submitted(&[0u8; 96]).is_err());
    }
}
