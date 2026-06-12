//! Live-RPC integration tests for the `chainio` read client.
//!
//! These are **gated behind the `CITRATE_RPC_URL` env var** and skip cleanly
//! when it is unset, so the default `cargo test` run is fully offline (the unit
//! tests in `src/` cover the envelope/ABI/selectors). Point `CITRATE_RPC_URL`
//! at a chain-40204 JSON-RPC endpoint to exercise the real network path:
//!
//! ```sh
//! CITRATE_RPC_URL=https://rpc.testnet-beta.citrate... cargo test -p chainio -- --nocapture
//! ```

use chainio::abi;

fn rpc_url() -> Option<String> {
    std::env::var("CITRATE_RPC_URL").ok()
}

#[tokio::test]
async fn chain_id_matches_canonical_40204() {
    let Some(url) = rpc_url() else {
        eprintln!("skipping: CITRATE_RPC_URL not set");
        return;
    };
    let client = chainio::rpc::RpcClient::new(url)
        .expect("CITRATE_RPC_URL must be https:// or loopback http:// (FUA-NODE-AGENT-06)");
    let id = client.eth_chain_id().await.expect("eth_chainId");
    assert_eq!(id, chainio::CHAIN_ID, "connected chain is not 40204");
}

#[tokio::test]
async fn marketplace_address_has_deployed_code() {
    let Some(url) = rpc_url() else {
        eprintln!("skipping: CITRATE_RPC_URL not set");
        return;
    };
    let client = chainio::rpc::RpcClient::new(url)
        .expect("CITRATE_RPC_URL must be https:// or loopback http:// (FUA-NODE-AGENT-06)");
    let marketplace =
        abi::address_from_hex(chainio::compute_marketplace()).expect("canonical address parses");
    let code = client.eth_get_code(marketplace).await.expect("eth_getCode");
    assert!(
        !code.is_empty(),
        "ComputeMarketplace {} has no deployed code on the connected chain",
        chainio::compute_marketplace()
    );
}

/// SELL-S0 gate: EVERY entry in the vendored canonical book (contracts +
/// aaStack) must have deployed code on the connected chain — not just the
/// marketplace. A re-roll that moves any address without a re-vendor
/// (`scripts/sync-addresses.sh`) fails here before the daemon transacts.
#[tokio::test]
async fn every_canonical_address_has_deployed_code() {
    let Some(url) = rpc_url() else {
        eprintln!("skipping: CITRATE_RPC_URL not set");
        return;
    };
    let client = chainio::rpc::RpcClient::new(url)
        .expect("CITRATE_RPC_URL must be https:// or loopback http:// (FUA-NODE-AGENT-06)");
    let mut empty = Vec::new();
    let mut checked = 0usize;
    for (name, addr_hex) in chainio::all_addresses() {
        let addr = abi::address_from_hex(addr_hex)
            .unwrap_or_else(|e| panic!("canonical address for {name} does not parse: {e:?}"));
        let code = client
            .eth_get_code(addr)
            .await
            .unwrap_or_else(|e| panic!("eth_getCode({name} {addr_hex}) failed: {e:?}"));
        if code.is_empty() {
            empty.push(format!("{name} {addr_hex}"));
        }
        checked += 1;
    }
    eprintln!("verified deployed code at {checked} canonical addresses");
    assert!(
        empty.is_empty(),
        "canonical addresses with NO deployed code on the connected chain \
         (stale vendored book? run `bash scripts/sync-addresses.sh`): {empty:?}"
    );
}

#[tokio::test]
async fn pricing_oracle_returns_a_price() {
    let Some(url) = rpc_url() else {
        eprintln!("skipping: CITRATE_RPC_URL not set");
        return;
    };
    let client = chainio::rpc::RpcClient::new(url)
        .expect("CITRATE_RPC_URL must be https:// or loopback http:// (FUA-NODE-AGENT-06)");
    let oracle =
        abi::address_from_hex(chainio::compute_pricing_oracle()).expect("canonical address parses");
    // saltPerPflopHour() should decode as a uint256 without erroring.
    let price = chainio::marketplace::live::salt_per_pflop_hour(&client, oracle)
        .await
        .expect("saltPerPflopHour read");
    eprintln!("saltPerPflopHour = {price} wei");
}
