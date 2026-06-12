//! `selectors` — hand-derived 4-byte Solidity function selectors.
//!
//! A function selector is the first four bytes of `keccak256(signature)`. We
//! derive them at runtime from the canonical signature strings (so the code is
//! self-documenting), and **pin every selector value in a unit test** so that a
//! change to a contract's ABI — or a typo in a signature here — can't silently
//! drift the calldata the agent sends on-chain (federation Rule 11 tripwire).
//!
//! Signatures are taken verbatim from `citrate-chain` contracts:
//! - `ComputeMarketplace`: `registerProvider(bytes32[])`, `bidOnJob(...)`,
//!   `assignBestBid(uint256)`, `startExecution(uint256)`,
//!   `submitCommitment(uint256,bytes32)`, `submitResult(uint256,bytes,bytes)`,
//!   `completeJob(uint256)`, `getJob(uint256)`, `getProvider(address)`.
//! - `ComputePricingOracle`: `saltPerPflopHour()`, `isPriceStale()`.
//! - `HeartbeatMonitor`: `heartbeat()`.

use tiny_keccak::{Hasher, Keccak};

/// Compute the 4-byte selector for a canonical function signature string.
pub fn selector(signature: &str) -> [u8; 4] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(signature.as_bytes());
    k.finalize(&mut out);
    [out[0], out[1], out[2], out[3]]
}

macro_rules! selector_fn {
    ($name:ident, $sig:literal) => {
        #[doc = concat!("Selector for `", $sig, "`.")]
        pub fn $name() -> [u8; 4] {
            selector($sig)
        }
    };
}

// --- ComputeMarketplace (read) ---
selector_fn!(get_provider, "getProvider(address)");
selector_fn!(get_job, "getJob(uint256)");
selector_fn!(get_provider_count, "getProviderCount()");

// --- ModelRegistry (read) ---
selector_fn!(get_model, "getModel(bytes32)");

// --- ContributionAccounting (read claimable + write claimRewards) ---
selector_fn!(claimable, "claimable(address)");
selector_fn!(claim_rewards, "claimRewards()");

// --- ComputeVerifier (read commitment status) ---
selector_fn!(get_record, "getRecord(uint256)");

// --- ComputeMarketplace (write — calldata builders live in `marketplace`) ---
selector_fn!(register_provider, "registerProvider(bytes32[])");
selector_fn!(bid_on_job, "bidOnJob(uint256,uint256,uint256)");
selector_fn!(assign_best_bid, "assignBestBid(uint256)");
selector_fn!(start_execution, "startExecution(uint256)");
selector_fn!(submit_commitment, "submitCommitment(uint256,bytes32)");
selector_fn!(submit_result, "submitResult(uint256,bytes,bytes)");
selector_fn!(complete_job, "completeJob(uint256)");

// --- ComputePricingOracle (read) ---
selector_fn!(salt_per_pflop_hour, "saltPerPflopHour()");
selector_fn!(is_price_stale, "isPriceStale()");

// --- HeartbeatMonitor (write) ---
selector_fn!(heartbeat, "heartbeat()");

// --- IPFSIncentivesV2/V3 (PIN-S6 pinning daemon) ---
// Signatures verbatim from `citrate-chain/contracts/src/IPFSIncentivesV2.sol`
// (V3 keeps these and adds the commit-reveal `commitChallenge`/`submitPoSt`
// shape, tracked in PIN-CR-S1). Reads + write calldata builders live in
// `pinning.rs`.
selector_fn!(pin_register_pinner, "registerPinner()");
selector_fn!(
    pin_seal_commit,
    "sealCommit(bytes32,uint256,bytes32,uint256,bytes32,bytes32,bytes32,bytes)"
);
selector_fn!(pin_challenge, "challenge(bytes32,uint256)");
selector_fn!(pin_submit_post, "submitPoSt(bytes32,uint256,bytes32,bytes32,uint256,bytes)");
selector_fn!(pin_claim, "claim(bytes32,uint256)");
selector_fn!(pin_return_bond, "returnBond(bytes32,uint256)");
selector_fn!(pin_get_pin, "getPin(address,bytes32,uint256)");
selector_fn!(pin_get_slot, "getSlot(bytes32,uint256)");
selector_fn!(pin_owed_of, "owedOf(address,bytes32,uint256)");
selector_fn!(pin_registered, "registered(address)");

#[cfg(test)]
mod tests {
    use super::*;

    fn hex4(s: [u8; 4]) -> String {
        format!("0x{:02x}{:02x}{:02x}{:02x}", s[0], s[1], s[2], s[3])
    }

    /// Pin EVERY selector. If a value here changes, a contract ABI changed and
    /// the agent's calldata would have silently drifted — fail loudly instead.
    #[test]
    fn selectors_are_pinned() {
        assert_eq!(hex4(get_provider()), "0x55f21eb7");
        assert_eq!(hex4(get_job()), "0xbf22c457");
        assert_eq!(hex4(get_provider_count()), "0x46ce4175");

        assert_eq!(hex4(get_model()), "0x21e7c498");

        assert_eq!(hex4(claimable()), "0x402914f5");
        assert_eq!(hex4(claim_rewards()), "0x372500ab");

        assert_eq!(hex4(get_record()), "0x03e9e609");

        assert_eq!(hex4(register_provider()), "0x0589cd44");
        assert_eq!(hex4(bid_on_job()), "0x18360fc2");
        assert_eq!(hex4(assign_best_bid()), "0x727495a4");
        assert_eq!(hex4(start_execution()), "0xc78ec18e");
        assert_eq!(hex4(submit_commitment()), "0xe6a3d9dc");
        assert_eq!(hex4(submit_result()), "0xbaa2c078");
        assert_eq!(hex4(complete_job()), "0xa1c0d32f");

        assert_eq!(hex4(salt_per_pflop_hour()), "0xeb2276eb");
        assert_eq!(hex4(is_price_stale()), "0x2f5df725");

        assert_eq!(hex4(heartbeat()), "0x3defb962");

        // IPFSIncentivesV2/V3 (PIN-S6)
        assert_eq!(hex4(pin_register_pinner()), "0xc0d2c428");
        assert_eq!(hex4(pin_seal_commit()), "0x51a0ed88");
        assert_eq!(hex4(pin_challenge()), "0xe2083c18");
        assert_eq!(hex4(pin_submit_post()), "0x43f6b201");
        assert_eq!(hex4(pin_claim()), "0x63f44968");
        assert_eq!(hex4(pin_return_bond()), "0x3ac9dfd3");
        assert_eq!(hex4(pin_get_pin()), "0x61793215");
        assert_eq!(hex4(pin_get_slot()), "0x68752a81");
        assert_eq!(hex4(pin_owed_of()), "0xabb31086");
        assert_eq!(hex4(pin_registered()), "0xb2dd5c07");
    }

    /// Sanity: a known ERC-20 selector to prove our keccak derivation is sound.
    #[test]
    fn keccak_derivation_matches_known_erc20_selector() {
        // transfer(address,uint256) → 0xa9059cbb (canonical, widely published).
        assert_eq!(hex4(selector("transfer(address,uint256)")), "0xa9059cbb");
    }
}
