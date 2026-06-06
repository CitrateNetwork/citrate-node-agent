//! `earnings` — sweep accrued rewards.
//!
//! After jobs complete, `ComputeMarketplace` routes payment through
//! `ContributionAccounting`, where it accrues in `claimable[provider]`. This
//! crate decides *when* to call `claimRewards()`: poll the balance, and once it
//! crosses a configured threshold (and no claim is already in flight), emit one
//! **unsigned** [`SignatureRequest`] for the signing surface — the agent holds no
//! keys (ADR-agent-signing / TD-17), same seam the job lifecycle uses.
//!
//! The decision is pure; the daemon does the `claimable(address)` read and the
//! broadcast/observe. Thresholding avoids dust-claiming (each claim costs gas),
//! and the in-flight guard makes repeated ticks idempotent (one claim, not N).

use chainio::abi::Address;
use chainio::accounting::encode_claim_rewards;
use lifecycle::{SignatureRequest, WriteIntent};

/// Configuration for the earnings sweep.
#[derive(Debug, Clone)]
pub struct EarningsConfig {
    /// Only claim once `claimable >= threshold_wei` (dust avoidance).
    pub threshold_wei: u128,
    /// The `ContributionAccounting` contract address (from the canonical book).
    pub accounting: Address,
    /// Chain id the claim tx must be signed for (40204).
    pub chain_id: u64,
}

/// What the daemon should do about earnings this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarningsAction {
    /// Emit this unsigned `claimRewards()` request.
    Claim(SignatureRequest),
    /// Below threshold, nothing accrued, or a claim is already in flight.
    Hold,
}

/// Decide whether to sweep, given the freshly-read `claimable_wei` and whether a
/// previously-emitted claim is still being observed (`claim_in_flight`).
pub fn plan_claim(
    claimable_wei: u128,
    claim_in_flight: bool,
    cfg: &EarningsConfig,
) -> EarningsAction {
    if claim_in_flight || claimable_wei == 0 || claimable_wei < cfg.threshold_wei {
        return EarningsAction::Hold;
    }
    EarningsAction::Claim(SignatureRequest {
        intent: WriteIntent::ClaimRewards,
        to: cfg.accounting,
        calldata: encode_claim_rewards(),
        value_wei: 0,
        chain_id: cfg.chain_id,
        context: format!("claimRewards ({claimable_wei} wei claimable)"),
        expires_block: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNTING: Address = [0x1a; 20];
    fn cfg() -> EarningsConfig {
        EarningsConfig {
            threshold_wei: 5 * 10u128.pow(18), // 5 SALT
            accounting: ACCOUNTING,
            chain_id: 40204,
        }
    }

    #[test]
    fn below_threshold_holds() {
        assert_eq!(
            plan_claim(4 * 10u128.pow(18), false, &cfg()),
            EarningsAction::Hold
        );
    }

    #[test]
    fn zero_claimable_holds() {
        assert_eq!(plan_claim(0, false, &cfg()), EarningsAction::Hold);
    }

    #[test]
    fn at_or_above_threshold_emits_one_claim() {
        let action = plan_claim(5 * 10u128.pow(18), false, &cfg());
        match action {
            EarningsAction::Claim(req) => {
                assert_eq!(req.intent, WriteIntent::ClaimRewards);
                assert_eq!(req.to, ACCOUNTING);
                assert_eq!(req.value_wei, 0);
                assert_eq!(req.chain_id, 40204);
                assert_eq!(req.calldata, encode_claim_rewards());
                assert_eq!(req.calldata.len(), 4); // selector only
                assert_eq!(req.expires_block, 0);
            }
            EarningsAction::Hold => panic!("expected a Claim at threshold"),
        }
    }

    #[test]
    fn in_flight_claim_is_not_re_emitted() {
        // Above threshold but a claim is already pending → idempotent Hold.
        assert_eq!(
            plan_claim(100 * 10u128.pow(18), true, &cfg()),
            EarningsAction::Hold
        );
    }
}
