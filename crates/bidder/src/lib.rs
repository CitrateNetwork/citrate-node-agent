//! `bidder` — cost-plus auto-bidding for the Citrate node agent (SELL-S1).
//!
//! The whole point of SELL-S1 is to bid **safely and profitably without getting
//! slashed**. Naive fixed-price bidding loses (scoring is 40% price / 30%
//! reputation / 20% load / 10% verification — new providers start at 0
//! reputation), and unsafe bidding gets the operator slashed (jobs that can't
//! finish in time time-out → 5% stake slash; jobs > 10 SALT auto-upgrade to a
//! ZKProof tier whose precompile is stubbed → guaranteed failure → slash).
//!
//! [`evaluate`] is a **pure** function: given a [`Job`], the current
//! [`ComputePricingOracle`] price, the operator [`Settings`], and runtime
//! [`Caps`], it returns a [`BidDecision`] — either a priced [`BidDecision::Bid`]
//! or a [`BidDecision::Skip`] with a machine-readable reason. No I/O, no clock,
//! no chain calls: callers pass in the current hour/day and provider load so
//! every branch is deterministically unit-testable offline (it mirrors every
//! scenario in `SELL-S1-node-agent-mvp.feature`).

use config::{Schedule, Weekday};

/// One SALT in wei (the chain's native settlement token uses 18 decimals, like
/// ether). `ComputeVerifier.VALUE_THRESHOLD` is `10 ether`.
pub const ONE_SALT_WEI: u128 = 1_000_000_000_000_000_000;

/// Commitment-tier cap: jobs whose `maxPrice` is **>= 10 SALT** are skipped in
/// S1. On-chain, `ComputeVerifier` auto-upgrades any job with
/// `value > VALUE_THRESHOLD (10 SALT)` from Commitment to ZKProof, and the ZK
/// precompile is stubbed (SELL planset R4 / defect "proof tier trap"). Bidding
/// at-or-above the threshold risks landing on the unsupported tier, so S1 stays
/// strictly below it. Lifted in SELL-S5 once ZK/TEE ships.
pub const COMMITMENT_CAP_WEI: u128 = 10 * ONE_SALT_WEI;

/// Cost-plus margin numerator/denominator: bid = estimated_cost * 1.15.
pub const MARGIN_NUM: u128 = 115;
pub const MARGIN_DEN: u128 = 100;

/// Bid ceiling as a fraction of `maxPrice`: never bid above 90% of maxPrice.
/// Leaves headroom under the on-chain `price <= maxPrice` ceiling and improves
/// the 40%-weighted price score.
pub const MAX_PRICE_CAP_NUM: u128 = 90;
pub const MAX_PRICE_CAP_DEN: u128 = 100;

/// Load cap: refuse new work once active jobs reach 80% of capacity, so a slot
/// is always reserved for in-flight completion (anti-slash headroom).
pub const LOAD_CAP_NUM: u64 = 80;
pub const LOAD_CAP_DEN: u64 = 100;

/// Deadline safety factor: only start a job if the remaining time is at least
/// `2x` the typical execution time (SELL-S1 "do not accept a job that cannot
/// finish before the deadline" + planset safety-gate).
pub const DEADLINE_SAFETY_FACTOR: u64 = 2;

/// The on-chain verification tier requested for a job. Mirrors
/// `ComputeVerifier.VerificationTier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTier {
    Commitment,
    ZKProof,
    Tee,
}

/// A marketplace job as seen by the bidder (decoded from `getJob` / `JobPosted`
/// plus the agent's own workload estimate).
#[derive(Debug, Clone, Copy)]
pub struct Job {
    /// Job id (for traceability in decisions/logs).
    pub id: u64,
    /// Maximum price the requester will pay, in wei.
    pub max_price_wei: u128,
    /// Requested verification tier.
    pub tier: VerificationTier,
    /// Estimated compute work for this job, in pflop-hours scaled by 1e18
    /// (i.e. fixed-point with 18 fractional digits, matching the oracle's
    /// `estimateCost` convention of dividing `pflopHours * price` by 1e18).
    pub estimated_pflop_hours_1e18: u128,
    /// Estimated wall-clock execution time for this job, in seconds.
    pub estimated_exec_secs: u64,
    /// Seconds remaining until the on-chain execution deadline (derived from
    /// `executionDeadline` blocks × block time, by the caller).
    pub secs_until_deadline: u64,
}

/// Oracle reading consulted for cost-plus pricing
/// (`ComputePricingOracle.saltPerPflopHour()` + staleness).
#[derive(Debug, Clone, Copy)]
pub struct ComputePricingOracle {
    /// `saltPerPflopHour()` in wei.
    pub salt_per_pflop_hour_wei: u128,
    /// `isPriceStale()` — a stale oracle must not be used to price a bid.
    pub stale: bool,
}

impl ComputePricingOracle {
    /// Estimated cost in wei for `job`, matching the oracle's on-chain
    /// `estimateCost` math: `pflopHours * saltPerPflopHour / 1e18`.
    pub fn estimated_cost_wei(&self, job: &Job) -> u128 {
        // pflop_hours is already ×1e18; multiplying by a wei price and dividing
        // by 1e18 yields a wei cost. Use u128 throughout (no float drift).
        job.estimated_pflop_hours_1e18
            .saturating_mul(self.salt_per_pflop_hour_wei)
            / ONE_SALT_WEI
    }
}

/// Operator settings relevant to bidding (subset of `compute.json` plus the
/// current local clock the caller samples).
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// Master participation switch (`compute.json.enabled`).
    pub enabled: bool,
    /// Participation schedule (`compute.json.schedule`).
    pub schedule: Schedule,
    /// Current local hour, 0..=23 (sampled by the caller).
    pub current_hour: u8,
    /// Current local weekday (sampled by the caller).
    pub current_day: Weekday,
}

/// Runtime provider capacity (from `getProvider`).
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// `ProviderProfile.currentActiveJobs`.
    pub current_active_jobs: u64,
    /// `ProviderProfile.maxConcurrentJobs`.
    pub max_concurrent_jobs: u64,
}

/// Why the bidder declined to bid. Stable, machine-readable strings (the
/// reputation/slash supervision surface and tests assert on these).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `compute.json.enabled == false`.
    Disabled,
    /// Current hour/day is outside the configured schedule window.
    OutsideSchedule,
    /// `maxPrice >= 10 SALT` → would auto-upgrade to the unsupported ZK tier.
    ExceedsCommitmentCap,
    /// Requested tier isn't Commitment (only Commitment is supported in S1).
    UnsupportedTier,
    /// Provider is at/over the 80% load cap.
    AtCapacity,
    /// Not enough time to finish before the execution deadline.
    DeadlineInfeasible,
    /// The pricing oracle is stale — refuse to price a bid off bad data.
    OracleStale,
    /// Cost-plus bid exceeds the price cap / there is no profitable price.
    Unprofitable,
}

impl SkipReason {
    /// Human/operator-facing reason string. The Commitment-cap string exactly
    /// matches the SELL-S1 acceptance scenario.
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::Disabled => "participation disabled in compute.json",
            SkipReason::OutsideSchedule => "outside the configured schedule window",
            SkipReason::ExceedsCommitmentCap => "exceeds Commitment-tier cap (10 SALT)",
            SkipReason::UnsupportedTier => "job requests a tier other than Commitment",
            SkipReason::AtCapacity => "provider at or above 80% of max concurrent jobs",
            SkipReason::DeadlineInfeasible => "execution deadline too close to finish safely",
            SkipReason::OracleStale => "ComputePricingOracle price is stale",
            SkipReason::Unprofitable => "no profitable bid under the price cap",
        }
    }
}

/// The outcome of evaluating a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BidDecision {
    /// Bid at `price_wei` (already cost-plus and capped). `estimated_cost_wei`
    /// is carried for logging/supervision.
    Bid {
        job_id: u64,
        price_wei: u128,
        estimated_cost_wei: u128,
    },
    /// Do not bid; `reason` explains why.
    Skip { job_id: u64, reason: SkipReason },
}

impl BidDecision {
    /// Convenience: did we decide to bid?
    pub fn is_bid(&self) -> bool {
        matches!(self, BidDecision::Bid { .. })
    }
    /// Convenience: the skip reason, if any.
    pub fn skip_reason(&self) -> Option<SkipReason> {
        match self {
            BidDecision::Skip { reason, .. } => Some(*reason),
            BidDecision::Bid { .. } => None,
        }
    }
}

/// Evaluate a job and decide whether/what to bid.
///
/// Gating order is deliberate (cheapest + safest checks first, pricing last):
///   (a) settings disabled                → Skip(Disabled)
///   (b) outside schedule window          → Skip(OutsideSchedule)
///   (c) maxPrice >= 10 SALT              → Skip(ExceedsCommitmentCap)
///       (and any non-Commitment tier)    → Skip(UnsupportedTier)
///   (d) active jobs >= 80% capacity      → Skip(AtCapacity)
///   (e) deadline < 2× exec time          → Skip(DeadlineInfeasible)
///   (f) cost-plus price, capped at 90%   → Bid (or Skip if unprofitable/stale)
pub fn evaluate(
    job: &Job,
    oracle: &ComputePricingOracle,
    settings: &Settings,
    caps: &Caps,
) -> BidDecision {
    let skip = |reason| BidDecision::Skip {
        job_id: job.id,
        reason,
    };

    // (a) participation switch.
    if !settings.enabled {
        return skip(SkipReason::Disabled);
    }

    // (b) schedule window.
    if !settings
        .schedule
        .in_window(settings.current_hour, settings.current_day)
    {
        return skip(SkipReason::OutsideSchedule);
    }

    // (c) Commitment-tier safety: the >= 10 SALT cap, then the explicit tier.
    if job.max_price_wei >= COMMITMENT_CAP_WEI {
        return skip(SkipReason::ExceedsCommitmentCap);
    }
    if job.tier != VerificationTier::Commitment {
        return skip(SkipReason::UnsupportedTier);
    }

    // (d) load cap: skip once active >= 80% of capacity. With zero capacity the
    // provider can't take work at all.
    if caps.max_concurrent_jobs == 0 {
        return skip(SkipReason::AtCapacity);
    }
    // active * 100 >= max * 80  ⇔  active >= 80% of max (integer-exact, no float).
    if (caps.current_active_jobs as u128) * (LOAD_CAP_DEN as u128)
        >= (caps.max_concurrent_jobs as u128) * (LOAD_CAP_NUM as u128)
    {
        return skip(SkipReason::AtCapacity);
    }

    // (e) deadline feasibility: need >= 2× typical execution time of headroom.
    let required = (job.estimated_exec_secs as u128) * (DEADLINE_SAFETY_FACTOR as u128);
    if (job.secs_until_deadline as u128) < required {
        return skip(SkipReason::DeadlineInfeasible);
    }

    // (f) cost-plus pricing off the oracle.
    if oracle.stale {
        return skip(SkipReason::OracleStale);
    }
    let cost = oracle.estimated_cost_wei(job);
    // bid = cost * 1.15
    let cost_plus = cost.saturating_mul(MARGIN_NUM) / MARGIN_DEN;
    // ceiling = 90% of maxPrice
    let ceiling = job.max_price_wei.saturating_mul(MAX_PRICE_CAP_NUM) / MAX_PRICE_CAP_DEN;
    // capped at 90% of maxPrice
    let price = cost_plus.min(ceiling);

    // If even the capped price can't cover cost (cost-plus above the ceiling),
    // bidding is unprofitable — don't take a loss.
    if price < cost || price == 0 {
        return skip(SkipReason::Unprofitable);
    }

    BidDecision::Bid {
        job_id: job.id,
        price_wei: price,
        estimated_cost_wei: cost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A baseline that bids: enabled, always-on, 4 SALT Commitment job, plenty of
    // capacity and deadline headroom, fresh oracle.
    fn ok_job() -> Job {
        Job {
            id: 7,
            max_price_wei: 4 * ONE_SALT_WEI,
            tier: VerificationTier::Commitment,
            // 1 pflop-hour of work (×1e18).
            estimated_pflop_hours_1e18: ONE_SALT_WEI,
            estimated_exec_secs: 600,
            secs_until_deadline: 3600,
        }
    }
    fn fresh_oracle() -> ComputePricingOracle {
        // 1 SALT per pflop-hour → 1 SALT estimated cost for the ok_job above.
        ComputePricingOracle {
            salt_per_pflop_hour_wei: ONE_SALT_WEI,
            stale: false,
        }
    }
    fn on_settings() -> Settings {
        Settings {
            enabled: true,
            schedule: Schedule::Always,
            current_hour: 12,
            current_day: Weekday::Wed,
        }
    }
    fn roomy_caps() -> Caps {
        Caps {
            current_active_jobs: 0,
            max_concurrent_jobs: 10,
        }
    }

    // --- Scenario: disabled means no participation ---
    #[test]
    fn disabled_does_not_bid() {
        let mut s = on_settings();
        s.enabled = false;
        let d = evaluate(&ok_job(), &fresh_oracle(), &s, &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::Disabled));
        assert!(!d.is_bid());
    }

    // --- Scenario: schedule window is honored (nights, noon → no bid) ---
    #[test]
    fn nights_at_noon_does_not_bid() {
        let s = Settings {
            enabled: true,
            schedule: Schedule::Nights,
            current_hour: 12,
            current_day: Weekday::Tue,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &s, &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::OutsideSchedule));
    }

    #[test]
    fn nights_at_night_bids() {
        let s = Settings {
            enabled: true,
            schedule: Schedule::Nights,
            current_hour: 23,
            current_day: Weekday::Tue,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &s, &roomy_caps());
        assert!(d.is_bid());
    }

    #[test]
    fn weekends_off_on_weekday_does_not_bid() {
        let s = Settings {
            enabled: true,
            schedule: Schedule::Weekends,
            current_hour: 12,
            current_day: Weekday::Mon,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &s, &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::OutsideSchedule));
    }

    // --- Scenario: high-value jobs are skipped until ZK is supported ---
    #[test]
    fn twelve_salt_exceeds_commitment_cap() {
        let mut j = ok_job();
        j.max_price_wei = 12 * ONE_SALT_WEI;
        let d = evaluate(&j, &fresh_oracle(), &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::ExceedsCommitmentCap));
        // Exact acceptance-test reason string.
        assert_eq!(
            d.skip_reason().unwrap().as_str(),
            "exceeds Commitment-tier cap (10 SALT)"
        );
    }

    #[test]
    fn exactly_ten_salt_is_capped_out() {
        // The on-chain rule auto-upgrades value > 10 SALT, but the task/feature
        // cap is >= 10 SALT — exactly 10 must not bid in S1.
        let mut j = ok_job();
        j.max_price_wei = COMMITMENT_CAP_WEI;
        let d = evaluate(&j, &fresh_oracle(), &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::ExceedsCommitmentCap));
    }

    #[test]
    fn just_under_ten_salt_is_allowed() {
        let mut j = ok_job();
        j.max_price_wei = COMMITMENT_CAP_WEI - 1;
        // Make cost small enough to stay under the 90% cap.
        let oracle = ComputePricingOracle {
            salt_per_pflop_hour_wei: ONE_SALT_WEI,
            stale: false,
        };
        let d = evaluate(&j, &oracle, &on_settings(), &roomy_caps());
        assert!(d.is_bid(), "9.999… SALT Commitment job should bid");
    }

    #[test]
    fn non_commitment_tier_is_unsupported() {
        let mut j = ok_job();
        j.tier = VerificationTier::ZKProof;
        let d = evaluate(&j, &fresh_oracle(), &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::UnsupportedTier));
    }

    // --- Scenario: bid is cost-plus and never exceeds maxPrice ---
    #[test]
    fn bid_is_cost_times_1_15_when_under_cap() {
        // cost = 1 SALT, maxPrice = 4 SALT. cost*1.15 = 1.15 SALT < 90% cap (3.6).
        let d = evaluate(&ok_job(), &fresh_oracle(), &on_settings(), &roomy_caps());
        match d {
            BidDecision::Bid {
                price_wei,
                estimated_cost_wei,
                ..
            } => {
                assert_eq!(estimated_cost_wei, ONE_SALT_WEI);
                assert_eq!(price_wei, ONE_SALT_WEI * 115 / 100);
                assert!(price_wei <= ok_job().max_price_wei);
            }
            other => panic!("expected Bid, got {other:?}"),
        }
    }

    #[test]
    fn bid_is_capped_at_90_percent_of_max_price() {
        // Make cost huge so cost*1.15 exceeds 90% of maxPrice → clamp to ceiling.
        let oracle = ComputePricingOracle {
            // 10 SALT/pflop-hour × 1 pflop-hour = 10 SALT cost (above maxPrice).
            salt_per_pflop_hour_wei: 10 * ONE_SALT_WEI,
            stale: false,
        };
        // Use a job whose cost is below the 90% ceiling but cost*1.15 is above it,
        // so the clamp engages and the bid is still profitable.
        let mut j = ok_job();
        j.max_price_wei = 4 * ONE_SALT_WEI; // ceiling 3.6 SALT
        j.estimated_pflop_hours_1e18 = ONE_SALT_WEI / 3; // cost ≈ 3.333 SALT
        let d = evaluate(&j, &oracle, &on_settings(), &roomy_caps());
        match d {
            BidDecision::Bid { price_wei, .. } => {
                let ceiling = j.max_price_wei * 90 / 100;
                assert_eq!(price_wei, ceiling, "should clamp to 90% of maxPrice");
                assert!(price_wei < j.max_price_wei);
            }
            other => panic!("expected clamped Bid, got {other:?}"),
        }
    }

    #[test]
    fn unprofitable_when_cost_above_ceiling() {
        // cost so high that even the 90% ceiling can't cover it → Skip.
        let oracle = ComputePricingOracle {
            salt_per_pflop_hour_wei: 100 * ONE_SALT_WEI,
            stale: false,
        };
        let d = evaluate(&ok_job(), &oracle, &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::Unprofitable));
    }

    // --- Scenario: does not bid at >= 80% of maxConcurrentJobs ---
    #[test]
    fn at_80_percent_capacity_does_not_bid() {
        let caps = Caps {
            current_active_jobs: 8,
            max_concurrent_jobs: 10,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &on_settings(), &caps);
        assert_eq!(d.skip_reason(), Some(SkipReason::AtCapacity));
    }

    #[test]
    fn at_70_percent_capacity_still_bids() {
        let caps = Caps {
            current_active_jobs: 7,
            max_concurrent_jobs: 10,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &on_settings(), &caps);
        assert!(d.is_bid());
    }

    #[test]
    fn zero_capacity_does_not_bid() {
        let caps = Caps {
            current_active_jobs: 0,
            max_concurrent_jobs: 0,
        };
        let d = evaluate(&ok_job(), &fresh_oracle(), &on_settings(), &caps);
        assert_eq!(d.skip_reason(), Some(SkipReason::AtCapacity));
    }

    // --- Scenario: do not accept a job that cannot finish before the deadline ---
    #[test]
    fn infeasible_deadline_does_not_bid() {
        let mut j = ok_job();
        j.estimated_exec_secs = 600;
        j.secs_until_deadline = 900; // < 2×600 = 1200
        let d = evaluate(&j, &fresh_oracle(), &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::DeadlineInfeasible));
    }

    #[test]
    fn exactly_2x_deadline_is_feasible() {
        let mut j = ok_job();
        j.estimated_exec_secs = 600;
        j.secs_until_deadline = 1200; // exactly 2×
        let d = evaluate(&j, &fresh_oracle(), &on_settings(), &roomy_caps());
        assert!(d.is_bid());
    }

    // --- Oracle staleness guard ---
    #[test]
    fn stale_oracle_does_not_bid() {
        let oracle = ComputePricingOracle {
            salt_per_pflop_hour_wei: ONE_SALT_WEI,
            stale: true,
        };
        let d = evaluate(&ok_job(), &oracle, &on_settings(), &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::OracleStale));
    }

    // --- Gating order: disabled beats every other skip reason ---
    #[test]
    fn disabled_takes_precedence_over_other_skips() {
        let mut s = on_settings();
        s.enabled = false;
        let mut j = ok_job();
        j.max_price_wei = 12 * ONE_SALT_WEI; // would also exceed cap
        let d = evaluate(&j, &fresh_oracle(), &s, &roomy_caps());
        assert_eq!(d.skip_reason(), Some(SkipReason::Disabled));
    }

    #[test]
    fn commitment_cap_constant_is_ten_salt() {
        assert_eq!(COMMITMENT_CAP_WEI, 10_000_000_000_000_000_000);
        assert_eq!(ONE_SALT_WEI, 1_000_000_000_000_000_000);
    }
}
