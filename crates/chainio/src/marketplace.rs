//! `marketplace` — typed encode/decode for the specific contract READ calls
//! SELL-S1 needs, plus calldata builders for the writes the agent broadcasts.
//!
//! Read calls (decoded into typed Rust):
//! - `ComputeMarketplace.getProvider(address) -> ProviderProfile`
//! - `ComputeMarketplace.getJob(uint256) -> Job`
//! - `ComputePricingOracle.saltPerPflopHour() -> uint256`
//! - `ComputePricingOracle.isPriceStale() -> bool`
//!
//! Write calldata builders (signed/broadcast elsewhere — this crate holds no
//! keys): `registerProvider`, `bidOnJob`, `assignBestBid`, `startExecution`,
//! `submitCommitment`, `submitResult`, `completeJob`. (Heartbeat calldata lives
//! in the `heartbeat` crate.)

use crate::abi::{self, AbiError, Address, Decoder, Word};
use crate::selectors;

/// Decoded `ComputeMarketplace.ProviderProfile`.
///
/// Field order matches the Solidity struct exactly (all fields static, so the
/// return is a flat sequence of words).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderProfile {
    pub is_registered: bool,
    pub stake_wei: u128,
    pub total_jobs_completed: u128,
    pub total_jobs_failed: u128,
    pub reputation_score_bps: u128,
    pub current_active_jobs: u128,
    pub max_concurrent_jobs: u128,
}

impl ProviderProfile {
    /// Decode the ABI return of `getProvider(address)`.
    pub fn decode(data: &[u8]) -> Result<Self, AbiError> {
        let mut d = Decoder::new(data);
        Ok(ProviderProfile {
            is_registered: d.bool()?,
            stake_wei: d.u128()?,
            total_jobs_completed: d.u128()?,
            total_jobs_failed: d.u128()?,
            reputation_score_bps: d.u128()?,
            current_active_jobs: d.u128()?,
            max_concurrent_jobs: d.u128()?,
        })
    }
}

/// On-chain job lifecycle state (`ComputeMarketplace.JobState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Posted,
    Bidding,
    Assigned,
    Executing,
    Verifying,
    Completed,
    Expired,
    Timeout,
    Failed,
    Disputed,
}

impl JobState {
    /// Map the `uint8` enum discriminant to a [`JobState`].
    pub fn from_u8(v: u8) -> Result<Self, AbiError> {
        Ok(match v {
            0 => JobState::Posted,
            1 => JobState::Bidding,
            2 => JobState::Assigned,
            3 => JobState::Executing,
            4 => JobState::Verifying,
            5 => JobState::Completed,
            6 => JobState::Expired,
            7 => JobState::Timeout,
            8 => JobState::Failed,
            9 => JobState::Disputed,
            _ => return Err(AbiError::Overflow),
        })
    }
}

/// Verification tier (`ComputeVerifier.VerificationTier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTier {
    Commitment,
    ZKProof,
    Tee,
}

impl VerificationTier {
    pub fn from_u8(v: u8) -> Result<Self, AbiError> {
        Ok(match v {
            0 => VerificationTier::Commitment,
            1 => VerificationTier::ZKProof,
            2 => VerificationTier::Tee,
            _ => return Err(AbiError::Overflow),
        })
    }
}

/// Decoded `ComputeMarketplace.Job` — the static fields SELL-S1 needs.
///
/// The Solidity `Job` struct contains a dynamic `bytes inputHash` field, so the
/// tuple is ABI-encoded dynamically: the outer return is a single offset word
/// pointing at the tuple, and within the tuple `inputHash` occupies a head
/// *offset* word (the bytes payload lives in the tuple's tail, which S1 does not
/// need). We read the static head fields by position and skip the dynamic
/// `inputHash` head word and `modelHash` (a `bytes32`, kept as a raw word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub id: u128,
    pub requester: Address,
    pub model_hash: Word,
    pub max_price_wei: u128,
    pub tier: VerificationTier,
    pub state: JobState,
    pub assigned_provider: Address,
    pub escrow_wei: u128,
    pub bid_deadline_block: u128,
    pub execution_deadline_block: u128,
    pub created_at_block: u128,
    pub bid_count: u128,
    /// PBA-L6b-021: the job's `inputHash` when it is exactly 32 bytes (the SDK
    /// default: `keccak256(input)`). `None` for any other length or a malformed
    /// tail; the executor then refuses to run the job (fail closed) because it
    /// cannot bind the off-chain input to what the requester posted.
    pub input_hash: Option<Word>,
}

impl Job {
    /// Decode the ABI return of `getJob(uint256)`.
    pub fn decode(data: &[u8]) -> Result<Self, AbiError> {
        let mut d = Decoder::new(data);
        // Outer: a single dynamic tuple → leading offset word (typically 0x20).
        // We don't need its value because the tuple head immediately follows in
        // the standard single-return layout; consume it.
        let tuple_offset = d.word()?;

        let id = d.u128()?;
        let requester = d.address()?;
        let model_hash = d.u256_word()?; // bytes32, raw
        // inputHash is `bytes` (dynamic): its head slot is an offset we skip.
        let input_hash_offset = d.word()?;
        let max_price_wei = d.u128()?;
        let tier = VerificationTier::from_u8(d.u8_enum()?)?;
        let state = JobState::from_u8(d.u8_enum()?)?;
        let assigned_provider = d.address()?;
        let escrow_wei = d.u128()?;
        let bid_deadline_block = d.u128()?;
        let execution_deadline_block = d.u128()?;
        let created_at_block = d.u128()?;
        let bid_count = d.u128()?;

        Ok(Job {
            id,
            requester,
            model_hash,
            max_price_wei,
            tier,
            state,
            assigned_provider,
            escrow_wei,
            bid_deadline_block,
            execution_deadline_block,
            created_at_block,
            bid_count,
            input_hash: decode_input_hash(data, &tuple_offset, &input_hash_offset),
        })
    }
}

/// Read the 32-byte `inputHash` from the job tuple's tail, with every offset
/// and length checked (no overflow, no out-of-bounds slice). Returns `None` for
/// a malformed tail or a length other than 32: the static head decode never
/// fails because of it, but the executor fails closed on `None`.
fn decode_input_hash(data: &[u8], tuple_offset: &Word, rel_offset: &Word) -> Option<Word> {
    let word_usize = |w: &Word| -> Option<usize> {
        if w[0..24].iter().any(|&b| b != 0) {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&w[24..32]);
        usize::try_from(u64::from_be_bytes(b)).ok()
    };
    let len_at = word_usize(tuple_offset)?.checked_add(word_usize(rel_offset)?)?;
    let len_end = len_at.checked_add(32)?;
    let len_word: Word = data.get(len_at..len_end)?.try_into().ok()?;
    if word_usize(&len_word)? != 32 {
        return None;
    }
    data.get(len_end..len_end.checked_add(32)?)?.try_into().ok()
}

/// Decode `saltPerPflopHour() -> uint256` (wei).
pub fn decode_salt_per_pflop_hour(data: &[u8]) -> Result<u128, AbiError> {
    Decoder::new(data).u128()
}

/// Decode `isPriceStale() -> bool`.
pub fn decode_is_price_stale(data: &[u8]) -> Result<bool, AbiError> {
    Decoder::new(data).bool()
}

// ---- calldata builders (READ) ----

/// `getProvider(address)` calldata.
pub fn encode_get_provider(provider: Address) -> Vec<u8> {
    abi::encode_call(selectors::get_provider(), &[abi::word_from_address(provider)])
}

/// `getJob(uint256)` calldata.
pub fn encode_get_job(job_id: u128) -> Vec<u8> {
    abi::encode_call(selectors::get_job(), &[abi::word_from_u128(job_id)])
}

/// `saltPerPflopHour()` calldata (no args).
pub fn encode_salt_per_pflop_hour() -> Vec<u8> {
    abi::encode_call(selectors::salt_per_pflop_hour(), &[])
}

/// `isPriceStale()` calldata (no args).
pub fn encode_is_price_stale() -> Vec<u8> {
    abi::encode_call(selectors::is_price_stale(), &[])
}

// ---- calldata builders (WRITE) ----

/// `bidOnJob(uint256 jobId, uint256 price, uint256 estimatedLatency)`.
pub fn encode_bid_on_job(job_id: u128, price_wei: u128, estimated_latency_ms: u128) -> Vec<u8> {
    abi::encode_call(
        selectors::bid_on_job(),
        &[
            abi::word_from_u128(job_id),
            abi::word_from_u128(price_wei),
            abi::word_from_u128(estimated_latency_ms),
        ],
    )
}

/// `assignBestBid(uint256 jobId)`.
pub fn encode_assign_best_bid(job_id: u128) -> Vec<u8> {
    abi::encode_call(selectors::assign_best_bid(), &[abi::word_from_u128(job_id)])
}

/// `startExecution(uint256 jobId)`.
pub fn encode_start_execution(job_id: u128) -> Vec<u8> {
    abi::encode_call(selectors::start_execution(), &[abi::word_from_u128(job_id)])
}

/// `submitCommitment(uint256 jobId, bytes32 commitment)`.
pub fn encode_submit_commitment(job_id: u128, commitment: Word) -> Vec<u8> {
    abi::encode_call(
        selectors::submit_commitment(),
        &[abi::word_from_u128(job_id), commitment],
    )
}

/// `completeJob(uint256 jobId)`.
pub fn encode_complete_job(job_id: u128) -> Vec<u8> {
    abi::encode_call(selectors::complete_job(), &[abi::word_from_u128(job_id)])
}

/// `submitResult(uint256 jobId, bytes outputHash, bytes proof)`.
///
/// Two dynamic `bytes` arguments. The head is three words —
/// `[ jobId | offset(outputHash) | offset(proof) ]` — where each offset is
/// measured from the start of the argument block (immediately after the 4-byte
/// selector). The two `bytes` tails follow in order. For the Commitment tier,
/// `output_hash = keccak256(output)` and `proof = commitment(32)‖nonce(32)‖output`
/// (the exact layout `ComputeVerifier._verifyCommitment` decodes).
pub fn encode_submit_result(job_id: u128, output_hash: &[u8], proof: &[u8]) -> Vec<u8> {
    const HEAD_LEN: usize = 3 * 32; // jobId + 2 offset words
    let output_tail = abi::encode_bytes_tail(output_hash);
    let proof_tail = abi::encode_bytes_tail(proof);
    let off_output = HEAD_LEN as u128;
    let off_proof = (HEAD_LEN + output_tail.len()) as u128;

    let mut out = Vec::with_capacity(4 + HEAD_LEN + output_tail.len() + proof_tail.len());
    out.extend_from_slice(&selectors::submit_result());
    out.extend_from_slice(&abi::word_from_u128(job_id));
    out.extend_from_slice(&abi::word_from_u128(off_output));
    out.extend_from_slice(&abi::word_from_u128(off_proof));
    out.extend_from_slice(&output_tail);
    out.extend_from_slice(&proof_tail);
    out
}

/// `registerProvider(bytes32[] supportedModels)`.
///
/// One dynamic `bytes32[]` argument: head is a single offset word (0x20), tail
/// is `[length, elem0, elem1, …]`.
pub fn encode_register_provider(supported_models: &[Word]) -> Vec<u8> {
    let mut args: Vec<Word> = Vec::with_capacity(2 + supported_models.len());
    // head: offset to the array data = 0x20 (one word past the head).
    args.push(abi::word_from_u128(0x20));
    // tail: array length, then each element.
    args.push(abi::word_from_u128(supported_models.len() as u128));
    args.extend_from_slice(supported_models);
    abi::encode_call(selectors::register_provider(), &args)
}

/// `resultVerifiedAt(uint256 jobId)` calldata.
pub fn encode_result_verified_at(job_id: u128) -> Vec<u8> {
    abi::encode_call(selectors::result_verified_at(), &[abi::word_from_u128(job_id)])
}

/// `disputeResolvedForProvider(uint256 jobId)` calldata.
pub fn encode_dispute_resolved_for_provider(job_id: u128) -> Vec<u8> {
    abi::encode_call(
        selectors::dispute_resolved_for_provider(),
        &[abi::word_from_u128(job_id)],
    )
}

// ---- live RPC convenience (used by the binary + integration tests) ----

/// Live-RPC read helpers. Always compiled (reqwest is a hard dependency), but
/// the *tests* that exercise them require `CITRATE_RPC_URL`.
pub mod live {
    use super::*;
    use crate::rpc::{RpcClient, RpcError};

    /// Read a provider profile from `ComputeMarketplace.getProvider`.
    pub async fn get_provider(
        client: &RpcClient,
        marketplace: Address,
        provider: Address,
    ) -> Result<ProviderProfile, RpcError> {
        let data = client
            .eth_call(marketplace, &encode_get_provider(provider))
            .await?;
        Ok(ProviderProfile::decode(&data)?)
    }

    /// Read a job from `ComputeMarketplace.getJob`.
    pub async fn get_job(
        client: &RpcClient,
        marketplace: Address,
        job_id: u128,
    ) -> Result<Job, RpcError> {
        let data = client.eth_call(marketplace, &encode_get_job(job_id)).await?;
        Ok(Job::decode(&data)?)
    }

    /// Read `ComputePricingOracle.saltPerPflopHour()`.
    pub async fn salt_per_pflop_hour(
        client: &RpcClient,
        oracle: Address,
    ) -> Result<u128, RpcError> {
        let data = client
            .eth_call(oracle, &encode_salt_per_pflop_hour())
            .await?;
        Ok(decode_salt_per_pflop_hour(&data)?)
    }

    /// Read `resultVerifiedAt(jobId)` (0 = not verified Valid yet).
    pub async fn result_verified_at(
        client: &RpcClient,
        marketplace: Address,
        job_id: u128,
    ) -> Result<u128, RpcError> {
        let data = client
            .eth_call(marketplace, &encode_result_verified_at(job_id))
            .await?;
        Ok(Decoder::new(&data).u128()?)
    }

    /// Read `disputeResolvedForProvider(jobId)`.
    pub async fn dispute_resolved_for_provider(
        client: &RpcClient,
        marketplace: Address,
        job_id: u128,
    ) -> Result<bool, RpcError> {
        let data = client
            .eth_call(marketplace, &encode_dispute_resolved_for_provider(job_id))
            .await?;
        Ok(Decoder::new(&data).bool()?)
    }

    /// Read `ComputePricingOracle.isPriceStale()`.
    pub async fn is_price_stale(client: &RpcClient, oracle: Address) -> Result<bool, RpcError> {
        let data = client.eth_call(oracle, &encode_is_price_stale()).await?;
        Ok(decode_is_price_stale(&data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{word_from_address, word_from_u128};

    fn push_word(buf: &mut Vec<u8>, w: Word) {
        buf.extend_from_slice(&w);
    }

    #[test]
    fn decodes_provider_profile() {
        // Build a synthetic ProviderProfile return: bool + 6×uint256.
        let mut data = Vec::new();
        let mut t = [0u8; 32];
        t[31] = 1; // isRegistered = true
        push_word(&mut data, t);
        push_word(&mut data, word_from_u128(1000 * 10u128.pow(18))); // stake
        push_word(&mut data, word_from_u128(12)); // completed
        push_word(&mut data, word_from_u128(1)); // failed
        push_word(&mut data, word_from_u128(9230)); // reputation bps
        push_word(&mut data, word_from_u128(3)); // currentActiveJobs
        push_word(&mut data, word_from_u128(10)); // maxConcurrentJobs

        let p = ProviderProfile::decode(&data).unwrap();
        assert!(p.is_registered);
        assert_eq!(p.stake_wei, 1000 * 10u128.pow(18));
        assert_eq!(p.total_jobs_completed, 12);
        assert_eq!(p.total_jobs_failed, 1);
        assert_eq!(p.reputation_score_bps, 9230);
        assert_eq!(p.current_active_jobs, 3);
        assert_eq!(p.max_concurrent_jobs, 10);
    }

    #[test]
    fn decodes_job_with_dynamic_inputhash() {
        // Layout: outer offset, then the tuple head:
        // id, requester, modelHash, inputHashOffset, maxPrice, tier, state,
        // assignedProvider, escrow, bidDeadline, execDeadline, createdAt,
        // bidCount. (inputHash tail omitted — not read.)
        let requester: Address = [0xaa; 20];
        let assigned: Address = [0xbb; 20];
        let mut model_hash = [0u8; 32];
        model_hash[0] = 0xde;
        model_hash[31] = 0xef;

        let mut data = Vec::new();
        push_word(&mut data, word_from_u128(0x20)); // outer tuple offset
        push_word(&mut data, word_from_u128(7)); // id
        push_word(&mut data, word_from_address(requester));
        push_word(&mut data, model_hash);
        push_word(&mut data, word_from_u128(0x1a0)); // inputHash offset (skipped)
        push_word(&mut data, word_from_u128(4 * 10u128.pow(18))); // maxPrice = 4 SALT
        push_word(&mut data, word_from_u128(0)); // tier = Commitment
        push_word(&mut data, word_from_u128(1)); // state = Bidding
        push_word(&mut data, word_from_address(assigned));
        push_word(&mut data, word_from_u128(4 * 10u128.pow(18))); // escrow
        push_word(&mut data, word_from_u128(100)); // bidDeadline
        push_word(&mut data, word_from_u128(200)); // execDeadline
        push_word(&mut data, word_from_u128(50)); // createdAt
        push_word(&mut data, word_from_u128(2)); // bidCount

        let j = Job::decode(&data).unwrap();
        assert_eq!(j.id, 7);
        assert_eq!(j.requester, requester);
        assert_eq!(j.model_hash, model_hash);
        assert_eq!(j.max_price_wei, 4 * 10u128.pow(18));
        assert_eq!(j.tier, VerificationTier::Commitment);
        assert_eq!(j.state, JobState::Bidding);
        assert_eq!(j.assigned_provider, assigned);
        assert_eq!(j.escrow_wei, 4 * 10u128.pow(18));
        assert_eq!(j.bid_deadline_block, 100);
        assert_eq!(j.execution_deadline_block, 200);
        assert_eq!(j.created_at_block, 50);
        assert_eq!(j.bid_count, 2);
    }

    /// A getJob return with a real `inputHash` tail at `tail_off` (relative to
    /// the tuple) holding `len` + `payload`.
    fn job_with_input_tail(tail_off: u128, len: u128, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        push_word(&mut data, word_from_u128(0x20));
        push_word(&mut data, word_from_u128(7));
        push_word(&mut data, word_from_address([0; 20]));
        push_word(&mut data, [0u8; 32]);
        push_word(&mut data, word_from_u128(tail_off));
        push_word(&mut data, word_from_u128(1));
        push_word(&mut data, word_from_u128(0));
        push_word(&mut data, word_from_u128(1));
        push_word(&mut data, word_from_address([0; 20]));
        for _ in 0..5 {
            push_word(&mut data, word_from_u128(0));
        }
        push_word(&mut data, word_from_u128(len));
        data.extend_from_slice(payload);
        data
    }

    // PBA-L6b-021: the 32-byte inputHash is decoded from the tuple tail.
    #[test]
    fn decodes_the_32_byte_input_hash_tail() {
        let h = [0x5a; 32];
        let j = Job::decode(&job_with_input_tail(0x1a0, 32, &h)).unwrap();
        assert_eq!(j.input_hash, Some(h));
    }

    // Any other length, or a hostile offset, yields None (executor fails closed)
    // without failing the static head decode and without panicking.
    #[test]
    fn non_32_byte_or_hostile_input_hash_is_none() {
        let j = Job::decode(&job_with_input_tail(0x1a0, 4, &[0xde, 0xad, 0xbe, 0xef])).unwrap();
        assert_eq!(j.input_hash, None);
        let j = Job::decode(&job_with_input_tail(0x1a0, 64, &[0u8; 64])).unwrap();
        assert_eq!(j.input_hash, None);
        let j = Job::decode(&job_with_input_tail(u64::MAX as u128, 32, &[1u8; 32])).unwrap();
        assert_eq!(j.input_hash, None);
        // Length claims 32 but the tail is truncated.
        let j = Job::decode(&job_with_input_tail(0x1a0, 32, &[1u8; 16])).unwrap();
        assert_eq!(j.input_hash, None);
    }

    #[test]
    fn decodes_high_value_zk_tier_job() {
        // A 12-SALT job whose tier is ZKProof (the auto-upgrade case S1 skips).
        let mut data = Vec::new();
        push_word(&mut data, word_from_u128(0x20));
        push_word(&mut data, word_from_u128(9));
        push_word(&mut data, word_from_address([0; 20]));
        push_word(&mut data, [0u8; 32]); // modelHash
        push_word(&mut data, word_from_u128(0x1a0)); // inputHash offset
        push_word(&mut data, word_from_u128(12 * 10u128.pow(18))); // 12 SALT
        push_word(&mut data, word_from_u128(1)); // tier = ZKProof
        push_word(&mut data, word_from_u128(1)); // state = Bidding
        push_word(&mut data, word_from_address([0; 20]));
        for _ in 0..5 {
            push_word(&mut data, word_from_u128(0));
        }
        let j = Job::decode(&data).unwrap();
        assert_eq!(j.max_price_wei, 12 * 10u128.pow(18));
        assert_eq!(j.tier, VerificationTier::ZKProof);
    }

    #[test]
    fn job_state_and_tier_map_round_trip() {
        assert_eq!(JobState::from_u8(5).unwrap(), JobState::Completed);
        assert_eq!(JobState::from_u8(9).unwrap(), JobState::Disputed);
        assert!(JobState::from_u8(10).is_err());
        assert_eq!(VerificationTier::from_u8(2).unwrap(), VerificationTier::Tee);
        assert!(VerificationTier::from_u8(3).is_err());
    }

    #[test]
    fn decodes_salt_per_pflop_hour() {
        let w = word_from_u128(5 * 10u128.pow(18));
        assert_eq!(decode_salt_per_pflop_hour(&w).unwrap(), 5 * 10u128.pow(18));
    }

    #[test]
    fn decodes_is_price_stale() {
        let mut t = [0u8; 32];
        t[31] = 1;
        assert!(decode_is_price_stale(&t).unwrap());
        assert!(!decode_is_price_stale(&[0u8; 32]).unwrap());
    }

    #[test]
    fn encodes_get_provider_calldata() {
        let provider: Address = [0xcc; 20];
        let call = encode_get_provider(provider);
        // selector(4) + 1 word(32).
        assert_eq!(call.len(), 36);
        assert_eq!(&call[0..4], &selectors::get_provider());
        // address is right-aligned in the arg word.
        assert_eq!(&call[4 + 12..4 + 32], &provider);
    }

    #[test]
    fn encodes_get_job_calldata() {
        let call = encode_get_job(42);
        assert_eq!(call.len(), 36);
        assert_eq!(&call[0..4], &selectors::get_job());
        assert_eq!(call[4 + 31], 42);
    }

    #[test]
    fn encodes_no_arg_read_calldata() {
        assert_eq!(encode_salt_per_pflop_hour().len(), 4);
        assert_eq!(&encode_salt_per_pflop_hour(), &selectors::salt_per_pflop_hour());
        assert_eq!(encode_is_price_stale().len(), 4);
    }

    #[test]
    fn encodes_bid_on_job_calldata() {
        let call = encode_bid_on_job(7, 1_150_000_000_000_000_000, 5000);
        // selector + 3 words.
        assert_eq!(call.len(), 4 + 96);
        assert_eq!(&call[0..4], &selectors::bid_on_job());
        // jobId word.
        assert_eq!(call[4 + 31], 7);
        // estimatedLatency word (last) = 5000 = 0x1388.
        assert_eq!(call[4 + 64 + 30], 0x13);
        assert_eq!(call[4 + 64 + 31], 0x88);
    }

    #[test]
    fn encodes_register_provider_with_dynamic_array() {
        let mut m0 = [0u8; 32];
        m0[31] = 0xab;
        let mut m1 = [0u8; 32];
        m1[31] = 0xcd;
        let call = encode_register_provider(&[m0, m1]);
        // selector + offset(0x20) + len(2) + 2 elements = 4 + 4*32.
        assert_eq!(call.len(), 4 + 128);
        assert_eq!(&call[0..4], &selectors::register_provider());
        // offset word = 0x20.
        assert_eq!(call[4 + 31], 0x20);
        // length word = 2.
        assert_eq!(call[4 + 32 + 31], 2);
        // first element last byte = 0xab.
        assert_eq!(call[4 + 64 + 31], 0xab);
        // second element last byte = 0xcd.
        assert_eq!(call[4 + 96 + 31], 0xcd);
    }

    #[test]
    fn encodes_submit_commitment_calldata() {
        let mut commitment = [0u8; 32];
        commitment[0] = 0x11;
        commitment[31] = 0x22;
        let call = encode_submit_commitment(3, commitment);
        assert_eq!(call.len(), 4 + 64);
        assert_eq!(&call[0..4], &selectors::submit_commitment());
        assert_eq!(call[4 + 31], 3);
        assert_eq!(&call[4 + 32..4 + 64], &commitment);
    }

    #[test]
    fn encodes_submit_result_calldata() {
        // outputHash = keccak256(output) is 32 bytes.
        let output_hash = [0x11u8; 32];
        // Commitment-tier proofData: commitment(32) ‖ nonce(32) ‖ output (5 bytes).
        let mut proof = Vec::new();
        proof.extend_from_slice(&[0x22u8; 32]); // commitment
        proof.extend_from_slice(&[0x33u8; 32]); // nonce
        proof.extend_from_slice(b"hello"); // output → 69 bytes total, pads to 96

        let call = encode_submit_result(5, &output_hash, &proof);
        assert_eq!(&call[0..4], &selectors::submit_result());
        let body = &call[4..];

        // head word 0: jobId = 5
        assert_eq!(body[31], 5);
        // head word 1: offset(outputHash) = 0x60 (3 words in)
        assert_eq!(body[32 + 31], 0x60);
        // head word 2: offset(proof) = 0x60 + 64 (outputHash tail) = 0xa0
        assert_eq!(body[64 + 31], 0xa0);
        // outputHash tail: length word = 32, then the 32 data bytes
        assert_eq!(body[96 + 31], 32);
        assert_eq!(&body[128..160], &output_hash);
        // proof tail: length word = 69, then commitment(0x22) leads the data
        assert_eq!(body[160 + 31], 69);
        assert_eq!(&body[192..224], &[0x22u8; 32]);
        // total: selector + head(96) + outputHash tail(64) + proof tail(128)
        assert_eq!(call.len(), 4 + 96 + 64 + 128);
    }

    #[test]
    fn encodes_single_uint_writes() {
        for (call, sel) in [
            (encode_assign_best_bid(8), selectors::assign_best_bid()),
            (encode_start_execution(8), selectors::start_execution()),
            (encode_complete_job(8), selectors::complete_job()),
        ] {
            assert_eq!(call.len(), 36);
            assert_eq!(&call[0..4], &sel);
            assert_eq!(call[4 + 31], 8);
        }
    }
}
