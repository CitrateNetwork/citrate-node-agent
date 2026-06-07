//! `addrbook` — canonical chain-40204 address book for the Citrate node agent.
//!
//! Reads from the federation-canonical contract-address table vendored at
//! `src/generated/addresses.json` (source-of-truth:
//! `citrate-chain/contracts/addresses/40204.json`). After a chain re-roll +
//! post-redeploy ceremony, run `bash scripts/sync-addresses.sh` from the
//! node-agent repo root to re-vendor the table — no inline edit required.
//!
//! Pre-WP-Z this module hand-mirrored the addresses as `&[(&str, &str)]`
//! constants and relied on a per-constant tripwire test to catch divergence.
//! That class of drift is now eliminated: the typed helpers read from the
//! same canonical the federation reads from.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Chain id this address book is valid for.
pub const CHAIN_ID: u64 = 40204;

/// Vendored copy of the federation-canonical contract-address table.
const ADDRESS_TABLE_JSON: &str = include_str!("generated/addresses.json");

/// Subset of the canonical table the node agent reads.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalTable {
    contracts: HashMap<String, String>,
    aa_stack: HashMap<String, String>,
}

/// Flat name → address map combining `contracts` + `aaStack`. Owned strings
/// are leaked into 'static memory at parse time so the public API can return
/// `&'static str` — the leak is sound because this map lives for the program
/// lifetime anyway.
static ADDRESS_BOOK: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let table: CanonicalTable = serde_json::from_str(ADDRESS_TABLE_JSON)
        .expect("src/generated/addresses.json is malformed at build time");
    let mut book = HashMap::with_capacity(table.contracts.len() + table.aa_stack.len());
    for (name, addr) in table.contracts.into_iter().chain(table.aa_stack.into_iter()) {
        let name_static: &'static str = Box::leak(name.into_boxed_str());
        let addr_static: &'static str = Box::leak(addr.into_boxed_str());
        book.insert(name_static, addr_static);
    }
    book
});

/// Look up a contract address by its canonical name (the Solidity contract
/// name, e.g. `"ComputeMarketplace"`). Returns `None` for unknown names.
pub fn address_for(name: &str) -> Option<&'static str> {
    ADDRESS_BOOK.get(name).copied()
}

macro_rules! typed_helper {
    ($fn_name:ident, $canonical:literal, $doc:literal) => {
        #[doc = $doc]
        pub fn $fn_name() -> &'static str {
            address_for($canonical).unwrap_or_else(|| {
                panic!(
                    "canonical address table missing {:?} (vendored \
                     src/generated/addresses.json may be stale — run \
                     `bash scripts/sync-addresses.sh`)",
                    $canonical
                )
            })
        }
    };
}

typed_helper!(
    compute_marketplace,
    "ComputeMarketplace",
    "ComputeMarketplace — registerProvider / bid / assign / start / submit / complete."
);
typed_helper!(
    compute_pool,
    "ComputePool",
    "ComputePool — pool membership and shared-node accounting (S6)."
);
typed_helper!(
    compute_verifier,
    "ComputeVerifier",
    "ComputeVerifier — Commitment-tier proof verification."
);
typed_helper!(
    heartbeat_monitor,
    "HeartbeatMonitor",
    "HeartbeatMonitor — liveness heartbeat / suspension watch."
);
typed_helper!(
    compute_pricing_oracle,
    "ComputePricingOracle",
    "ComputePricingOracle — cost-plus bidding reference prices."
);
typed_helper!(
    contribution_accounting,
    "ContributionAccounting",
    "ContributionAccounting — claimable rewards / claimRewards."
);
typed_helper!(
    bulk_compute_gateway,
    "BulkComputeGateway",
    "BulkComputeGateway — bulk job intake gateway."
);
typed_helper!(
    model_registry,
    "ModelRegistry",
    "ModelRegistry — model CID lookup for provisioning."
);
typed_helper!(
    wrapped_salt,
    "WrappedSALT",
    "WrappedSALT — ERC-20 wrapper for the native SALT settlement token."
);
typed_helper!(
    inference_router,
    "InferenceRouter",
    "InferenceRouter — inference request routing."
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: every typed helper resolves to a 20-byte hex address
    /// that comes from the vendored canonical. The exact addresses are
    /// asserted in the canonical's own tests + the explorer's PR2 test
    /// suite; here we just verify the shape so a malformed vendored copy
    /// is caught at this crate's test gate.
    #[test]
    fn typed_helpers_resolve_to_shape_correct_addresses() {
        assert_eq!(CHAIN_ID, 40204);

        let addresses = [
            ("compute_marketplace", compute_marketplace()),
            ("compute_pool", compute_pool()),
            ("compute_verifier", compute_verifier()),
            ("heartbeat_monitor", heartbeat_monitor()),
            ("compute_pricing_oracle", compute_pricing_oracle()),
            ("contribution_accounting", contribution_accounting()),
            ("bulk_compute_gateway", bulk_compute_gateway()),
            ("model_registry", model_registry()),
            ("wrapped_salt", wrapped_salt()),
            ("inference_router", inference_router()),
        ];
        let mut seen = std::collections::HashSet::new();
        for (label, addr) in addresses {
            assert!(
                addr.starts_with("0x") && addr.len() == 42,
                "{label} is not a 20-byte hex: {addr}"
            );
            assert!(
                seen.insert(addr.to_lowercase()),
                "{label} address collides with another helper: {addr}"
            );
        }
    }

    /// `address_for` resolves canonical names and rejects unknown ones.
    #[test]
    fn address_for_lookup() {
        assert_eq!(address_for("ComputeMarketplace"), Some(compute_marketplace()));
        assert_eq!(address_for("NotAContract"), None);
        assert_eq!(address_for("HeartbeatMonitor"), Some(heartbeat_monitor()));
        // EW-S1 AA stack also reachable via address_for.
        assert!(address_for("EntryPoint").is_some());
    }

    /// Defect D1 regression: the stale gui-native ComputeMarketplace address
    /// must NEVER appear anywhere in this address book.
    #[test]
    fn stale_gui_native_address_absent() {
        const STALE: &str = "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b";
        assert!(
            ADDRESS_BOOK.values().all(|addr| *addr != STALE),
            "stale gui-native address {STALE} leaked into the canonical book"
        );
        assert_eq!(address_for(STALE), None);
    }

    /// The vendored canonical includes every contract the typed helpers
    /// ask for — a missing name would surface as a panic at boot, not at
    /// test time. This test enumerates the helper inputs to make that
    /// guarantee explicit.
    #[test]
    fn canonical_has_every_typed_helper_name() {
        for name in [
            "ComputeMarketplace",
            "ComputePool",
            "ComputeVerifier",
            "HeartbeatMonitor",
            "ComputePricingOracle",
            "ContributionAccounting",
            "BulkComputeGateway",
            "ModelRegistry",
            "WrappedSALT",
            "InferenceRouter",
        ] {
            assert!(
                ADDRESS_BOOK.contains_key(name),
                "vendored src/generated/addresses.json is missing {name:?} — run `bash scripts/sync-addresses.sh`"
            );
        }
    }
}
