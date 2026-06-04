//! `addrbook` — canonical chain-40204 address book for the Citrate node agent.
//!
//! This module **MIRRORS** the canonical `citrate-chain`
//! `contracts/DEPLOYED_ADDRESSES.md` table (chain id `40204`, testnet-beta).
//! It is hand-mirrored on purpose so the node agent has a zero-dependency,
//! compile-time-checked source of contract addresses for the compute-critical
//! contracts it drives (marketplace, pool, verifier, heartbeat, oracle,
//! accounting, gateway, registry, wrapped SALT, inference router).
//!
//! Because this is a mirror, it can drift from the canonical table when chain
//! contracts are re-deployed or re-rolled. The `canonical_addresses` test in
//! this crate is the **divergence tripwire** (federation Rule 11): if anyone
//! changes a constant here without it matching the canonical table, the pinning
//! tests fail. To update after a chain re-roll, re-mirror from
//! `citrate-chain/contracts/DEPLOYED_ADDRESSES.md` and update the tests in the
//! same change. This is a documented design, not a TODO.

/// Chain id this address book is valid for.
pub const CHAIN_ID: u64 = 40204;

/// Canonical chain-40204 addresses for the compute-critical contracts the node
/// agent drives. Mirrored from `citrate-chain` `DEPLOYED_ADDRESSES.md`.
///
/// `(canonical_name, address)`. Names match the contract names in the canonical
/// table so the tripwire test reads 1:1 against it.
const ADDRESS_BOOK: &[(&str, &str)] = &[
    ("ComputeMarketplace", "0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6"),
    ("ComputePool", "0x8b36c15552394ce44173a29d054dc5ca482e65d3"),
    ("ComputeVerifier", "0x86d918808b48ad543c9c816b5303b7dbcb0e321f"),
    ("HeartbeatMonitor", "0x46773aeca885be65cd313b7d9bce9625767d40b5"),
    ("ComputePricingOracle", "0xa1eed6ae021504e2a1e310e6c0f7c1a0c5bf4647"),
    ("ContributionAccounting", "0x1afe987622ab5add275d2fd21248f77f5e00667f"),
    ("BulkComputeGateway", "0x7efc1eb17beff413e1af7fb3bb541e895c307300"),
    ("ModelRegistry", "0x077fbc3338a9e6bad90a3a041e6b7425689754ef"),
    ("WrappedSALT", "0x1f73bb479f397a34b5e3145e51d25bc5007273bf"),
    ("InferenceRouter", "0xad7c3135c1b9b3189208fd617b6b058c1c0469f3"),
];

/// Look up a contract address by its canonical name (as spelled in
/// `DEPLOYED_ADDRESSES.md`). Returns `None` for unknown / non-mirrored names.
pub fn address_for(name: &str) -> Option<&'static str> {
    ADDRESS_BOOK
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, addr)| *addr)
}

macro_rules! typed_helper {
    ($fn_name:ident, $canonical:literal, $doc:literal) => {
        #[doc = $doc]
        pub fn $fn_name() -> &'static str {
            // Safe: the canonical name is present in ADDRESS_BOOK by
            // construction, and the `canonical_addresses` test pins it.
            address_for($canonical).expect(concat!(
                "missing canonical address for ",
                $canonical,
                " in ADDRESS_BOOK"
            ))
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

    /// Divergence tripwire (Rule 11): pin EVERY compute-critical address to its
    /// canonical chain-40204 value from `citrate-chain` `DEPLOYED_ADDRESSES.md`.
    /// If a chain re-roll changes an address, re-mirror the book AND this test
    /// in the same change.
    #[test]
    fn canonical_addresses() {
        assert_eq!(CHAIN_ID, 40204);

        assert_eq!(
            compute_marketplace(),
            "0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6"
        );
        assert_eq!(compute_pool(), "0x8b36c15552394ce44173a29d054dc5ca482e65d3");
        assert_eq!(
            compute_verifier(),
            "0x86d918808b48ad543c9c816b5303b7dbcb0e321f"
        );
        assert_eq!(
            heartbeat_monitor(),
            "0x46773aeca885be65cd313b7d9bce9625767d40b5"
        );
        assert_eq!(
            compute_pricing_oracle(),
            "0xa1eed6ae021504e2a1e310e6c0f7c1a0c5bf4647"
        );
        assert_eq!(
            contribution_accounting(),
            "0x1afe987622ab5add275d2fd21248f77f5e00667f"
        );
        assert_eq!(
            bulk_compute_gateway(),
            "0x7efc1eb17beff413e1af7fb3bb541e895c307300"
        );
        assert_eq!(
            model_registry(),
            "0x077fbc3338a9e6bad90a3a041e6b7425689754ef"
        );
        assert_eq!(wrapped_salt(), "0x1f73bb479f397a34b5e3145e51d25bc5007273bf");
        assert_eq!(
            inference_router(),
            "0xad7c3135c1b9b3189208fd617b6b058c1c0469f3"
        );
    }

    /// `address_for` resolves canonical names and rejects unknown ones.
    #[test]
    fn address_for_lookup() {
        assert_eq!(
            address_for("ComputeMarketplace"),
            Some("0xf3f9f72ea2bb3f763b07390b7257da643b8ee9b6")
        );
        assert_eq!(address_for("NotAContract"), None);
        // Helper and map agree.
        assert_eq!(address_for("HeartbeatMonitor"), Some(heartbeat_monitor()));
    }

    /// Defect D1 regression: the stale gui-native ComputeMarketplace address
    /// must NEVER appear anywhere in this address book.
    #[test]
    fn stale_gui_native_address_absent() {
        const STALE: &str = "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b";
        assert!(
            ADDRESS_BOOK.iter().all(|(_, addr)| *addr != STALE),
            "stale gui-native address {STALE} leaked into the canonical book"
        );
        assert_eq!(address_for(STALE), None);
    }

    /// No duplicate names in the book (a copy-paste guard for the mirror).
    #[test]
    fn no_duplicate_names() {
        for i in 0..ADDRESS_BOOK.len() {
            for j in (i + 1)..ADDRESS_BOOK.len() {
                assert_ne!(
                    ADDRESS_BOOK[i].0, ADDRESS_BOOK[j].0,
                    "duplicate contract name in ADDRESS_BOOK"
                );
            }
        }
    }
}
