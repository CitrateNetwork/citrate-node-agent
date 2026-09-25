//! `bridge` — map decoded chain types (`chainio::marketplace`) into the pure
//! bidder's input types (`bidder`).
//!
//! This is the seam between "what the chain returned" and "what the bidding
//! decision needs". Keeping it a small, tested mapping means the bidder stays
//! free of chain/ABI concerns and the chain client stays free of pricing logic.

use bidder::{Caps, Job as BidJob, VerificationTier as BidTier};
use chainio::marketplace::{Job as ChainJob, ProviderProfile, VerificationTier as ChainTier};

/// Fallback block time (seconds) when the chain-derived value isn't available
/// (e.g. an idle devnet with non-advancing timestamps, or too few blocks).
/// Chain 40204 targets ~2s blocks. The live agent derives the real value from
/// block timestamps (`RpcClient::secs_per_block`) and only falls back to this.
pub const DEFAULT_SECS_PER_BLOCK: u64 = 2;

/// Map the on-chain verification tier into the bidder's tier enum.
pub fn map_tier(t: ChainTier) -> BidTier {
    match t {
        ChainTier::Commitment => BidTier::Commitment,
        ChainTier::ZKProof => BidTier::ZKProof,
        ChainTier::Tee => BidTier::Tee,
    }
}

/// Map a provider profile to the bidder's capacity view.
pub fn map_caps(p: &ProviderProfile) -> Caps {
    Caps {
        current_active_jobs: p.current_active_jobs as u64,
        max_concurrent_jobs: p.max_concurrent_jobs as u64,
    }
}

/// Build a [`bidder::Job`] from a decoded chain job plus the agent's own work
/// estimate (pflop-hours ×1e18 and typical execution seconds — provided by the
/// executor's profiling in later sprints; passed in here).
///
/// `current_block` + `secs_per_block` turn the block-number `executionDeadline`
/// into a seconds-until-deadline figure. `secs_per_block` is the chain-derived
/// value (or [`DEFAULT_SECS_PER_BLOCK`] when it can't be sampled).
pub fn map_job(
    job: &ChainJob,
    current_block: u128,
    secs_per_block: u64,
    estimated_pflop_hours_1e18: u128,
    estimated_exec_secs: u64,
) -> BidJob {
    let blocks_left = job
        .execution_deadline_block
        .saturating_sub(current_block);
    let secs_until_deadline = (blocks_left as u64).saturating_mul(secs_per_block);
    BidJob {
        id: job.id as u64,
        max_price_wei: job.max_price_wei,
        tier: map_tier(job.tier),
        estimated_pflop_hours_1e18,
        estimated_exec_secs,
        secs_until_deadline,
    }
}

/// PBA-L6b-025: the block a bid on `job` must expire at, or `None` when the
/// job is not open for bids (state other than Posted/Bidding, or the bid
/// deadline has been reached at `current_block`).
///
/// PBA-L6b-021 (R2 verifier follow-up): also `None` when the job's on-chain
/// `inputHash` is not a 32-byte keccak binding (`input_hash == None`, e.g. the
/// CID bytes citrate-sdk-marketplace's `postJobCalldata` accepts). The executor
/// refuses to run an input it cannot bind to the chain, so a job like that must
/// be declined BEFORE bidding — refusing it after winning would leave the job
/// to `timeoutJob`, which slashes the provider. Fail closed at bid time, never
/// after assignment.
pub fn bid_expires_block(job: &ChainJob, current_block: u128) -> Option<u128> {
    use chainio::marketplace::JobState;
    let open_state = matches!(job.state, JobState::Posted | JobState::Bidding);
    let bindable_input = job.input_hash.is_some();
    (open_state && bindable_input && current_block < job.bid_deadline_block)
        .then_some(job.bid_deadline_block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainio::marketplace::JobState;

    fn chain_job() -> ChainJob {
        ChainJob {
            id: 7,
            requester: [0xaa; 20],
            model_hash: [0u8; 32],
            max_price_wei: 4 * 10u128.pow(18),
            tier: ChainTier::Commitment,
            state: JobState::Bidding,
            assigned_provider: [0; 20],
            escrow_wei: 4 * 10u128.pow(18),
            bid_deadline_block: 100,
            execution_deadline_block: 1000,
            created_at_block: 50,
            bid_count: 1,
            input_hash: Some([0x11; 32]),
        }
    }

    #[test]
    fn maps_tier() {
        assert_eq!(map_tier(ChainTier::Commitment), BidTier::Commitment);
        assert_eq!(map_tier(ChainTier::ZKProof), BidTier::ZKProof);
        assert_eq!(map_tier(ChainTier::Tee), BidTier::Tee);
    }

    #[test]
    fn maps_caps() {
        let p = ProviderProfile {
            is_registered: true,
            stake_wei: 0,
            total_jobs_completed: 0,
            total_jobs_failed: 0,
            reputation_score_bps: 10000,
            current_active_jobs: 3,
            max_concurrent_jobs: 10,
        };
        let c = map_caps(&p);
        assert_eq!(c.current_active_jobs, 3);
        assert_eq!(c.max_concurrent_jobs, 10);
    }

    #[test]
    fn maps_job_and_converts_deadline_to_seconds() {
        // 3s/block (a chain-derived value, not the hardcoded default).
        let j = map_job(&chain_job(), 900, 3, 10u128.pow(18), 600);
        assert_eq!(j.id, 7);
        assert_eq!(j.max_price_wei, 4 * 10u128.pow(18));
        assert_eq!(j.tier, BidTier::Commitment);
        // 1000 - 900 = 100 blocks × 3s = 300s.
        assert_eq!(j.secs_until_deadline, 300);
        assert_eq!(j.estimated_exec_secs, 600);
    }

    #[test]
    fn past_deadline_is_zero_seconds_not_underflow() {
        let j = map_job(&chain_job(), 5000, DEFAULT_SECS_PER_BLOCK, 10u128.pow(18), 600);
        assert_eq!(j.secs_until_deadline, 0);
    }

    // PBA-L6b-025: only Posted/Bidding jobs before their bid deadline are open.
    #[test]
    fn l6b_025_bid_window_requires_open_state_and_live_deadline() {
        use chainio::marketplace::JobState;
        let mut j = chain_job(); // Bidding, bid deadline 100
        assert_eq!(bid_expires_block(&j, 99), Some(100));
        assert_eq!(bid_expires_block(&j, 100), None, "deadline reached");
        assert_eq!(bid_expires_block(&j, 5000), None, "deadline passed");
        j.state = JobState::Posted;
        assert_eq!(bid_expires_block(&j, 50), Some(100));
        for closed in [
            JobState::Assigned,
            JobState::Executing,
            JobState::Verifying,
            JobState::Completed,
            JobState::Expired,
            JobState::Timeout,
            JobState::Failed,
            JobState::Disputed,
        ] {
            j.state = closed;
            assert_eq!(bid_expires_block(&j, 50), None, "{closed:?} is not open for bids");
        }
    }

    // PBA-L6b-021 (R2 verifier): a job whose inputHash cannot be bound to the
    // delivered input (not a 32-byte keccak, e.g. CID bytes) is never bid on —
    // the executor would refuse it after winning and the provider would be
    // slashed by timeoutJob. A bindable job in the same window is still open.
    #[test]
    fn l6b_021_unbindable_input_hash_is_never_bid_on() {
        let mut j = chain_job(); // Bidding, bid deadline 100, bindable hash
        assert_eq!(
            bid_expires_block(&j, 50),
            Some(100),
            "control: bindable job is open"
        );
        j.input_hash = None;
        assert_eq!(
            bid_expires_block(&j, 50),
            None,
            "PBA-L6b-021: no bid on an unbindable inputHash (no slash path)"
        );
    }
}
