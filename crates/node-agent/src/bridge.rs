//! `bridge` — map decoded chain types (`chainio::marketplace`) into the pure
//! bidder's input types (`bidder`).
//!
//! This is the seam between "what the chain returned" and "what the bidding
//! decision needs". Keeping it a small, tested mapping means the bidder stays
//! free of chain/ABI concerns and the chain client stays free of pricing logic.

use bidder::{Caps, Job as BidJob, VerificationTier as BidTier};
use chainio::marketplace::{Job as ChainJob, ProviderProfile, VerificationTier as ChainTier};

/// Block time assumption for converting a block-number deadline into seconds.
/// Chain 40204 targets ~2s blocks; this is the conversion factor the agent uses
/// when estimating `secs_until_deadline` from `executionDeadline`.
pub const SECS_PER_BLOCK: u64 = 2;

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
/// `current_block` lets us turn the block-number `executionDeadline` into a
/// seconds-until-deadline figure via [`SECS_PER_BLOCK`].
pub fn map_job(
    job: &ChainJob,
    current_block: u128,
    estimated_pflop_hours_1e18: u128,
    estimated_exec_secs: u64,
) -> BidJob {
    let blocks_left = job
        .execution_deadline_block
        .saturating_sub(current_block);
    let secs_until_deadline = (blocks_left as u64).saturating_mul(SECS_PER_BLOCK);
    BidJob {
        id: job.id as u64,
        max_price_wei: job.max_price_wei,
        tier: map_tier(job.tier),
        estimated_pflop_hours_1e18,
        estimated_exec_secs,
        secs_until_deadline,
    }
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
        let j = map_job(&chain_job(), 900, 10u128.pow(18), 600);
        assert_eq!(j.id, 7);
        assert_eq!(j.max_price_wei, 4 * 10u128.pow(18));
        assert_eq!(j.tier, BidTier::Commitment);
        // 1000 - 900 = 100 blocks × 2s = 200s.
        assert_eq!(j.secs_until_deadline, 200);
        assert_eq!(j.estimated_exec_secs, 600);
    }

    #[test]
    fn past_deadline_is_zero_seconds_not_underflow() {
        let j = map_job(&chain_job(), 5000, 10u128.pow(18), 600);
        assert_eq!(j.secs_until_deadline, 0);
    }
}
