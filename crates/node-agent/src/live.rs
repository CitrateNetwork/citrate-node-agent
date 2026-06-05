//! `live` — production wiring for the daemon loop: real chain reads behind the
//! [`crate::daemon::MarketView`] trait, and the honest heartbeat sender.
//!
//! These are the real I/O implementations the binary uses when
//! `CITRATE_RPC_URL` + `CITRATE_PROVIDER_ADDRESS` are configured. They contain
//! no stub logic: every read is a real `eth_call`, and the heartbeat sender
//! tells the truth about the one capability the agent does not yet own — signing
//! (keys live in gui-native's keystore, broadcast lands in SELL-S2). It returns
//! an explicit error rather than faking a successful broadcast.

use bidder::{Caps, ComputePricingOracle};
use chainio::abi::{self, Address};
use chainio::rpc::RpcClient;
use heartbeat::{HeartbeatError, HeartbeatSender};

use crate::bridge;
use crate::daemon::{MarketSnapshot, MarketView};

/// Real chain reads for one provider + one target job id.
pub struct LiveMarketView {
    pub client: RpcClient,
    pub marketplace: Address,
    pub oracle: Address,
    pub provider: Address,
    pub job_id: u128,
    /// Agent's own per-job work estimate (pflop-hours ×1e18) until the profiler
    /// lands (S2).
    pub estimated_pflop_hours_1e18: u128,
    /// Agent's own typical execution-time estimate (seconds).
    pub estimated_exec_secs: u64,
}

impl MarketView for LiveMarketView {
    async fn refresh(&self) -> Result<MarketSnapshot, String> {
        // Provider profile (capacity + reputation).
        let profile =
            chainio::marketplace::live::get_provider(&self.client, self.marketplace, self.provider)
                .await
                .map_err(|e| format!("getProvider: {e}"))?;
        let caps: Caps = bridge::map_caps(&profile);

        // Oracle price + staleness.
        let salt_per_pflop_hour =
            chainio::marketplace::live::salt_per_pflop_hour(&self.client, self.oracle)
                .await
                .map_err(|e| format!("saltPerPflopHour: {e}"))?;
        let stale = chainio::marketplace::live::is_price_stale(&self.client, self.oracle)
            .await
            .map_err(|e| format!("isPriceStale: {e}"))?;
        let oracle = ComputePricingOracle {
            salt_per_pflop_hour_wei: salt_per_pflop_hour,
            stale,
        };

        // Target job + current block (to convert the deadline to seconds).
        let chain_job =
            chainio::marketplace::live::get_job(&self.client, self.marketplace, self.job_id)
                .await
                .map_err(|e| format!("getJob: {e}"))?;
        let current_block = self
            .client
            .eth_block_number()
            .await
            .map_err(|e| format!("blockNumber: {e}"))?;
        let job = bridge::map_job(
            &chain_job,
            current_block,
            self.estimated_pflop_hours_1e18,
            self.estimated_exec_secs,
        );

        Ok(MarketSnapshot {
            caps,
            reputation_bps: profile.reputation_score_bps as u32,
            job,
            oracle,
        })
    }
}

/// The honest heartbeat sender for the unsigned read-only agent.
///
/// The agent holds no keys (gui-native owns the keystore; signed broadcast is
/// SELL-S2). Rather than fake a successful `heartbeat()` broadcast — which would
/// be a lie that leaves the provider unknowingly headed for suspension — this
/// sender returns an explicit error every tick. The daemon loop records it in
/// `last_error` so the GUI's `/health` surfaces the real, un-broadcast state.
pub struct UnsignedHeartbeatSender;

impl HeartbeatSender for UnsignedHeartbeatSender {
    async fn send_heartbeat(&self, calldata: &[u8]) -> Result<(), HeartbeatError> {
        Err(HeartbeatError::Send(format!(
            "no signer configured: would broadcast heartbeat() calldata {} \
             (signing/broadcast lands in SELL-S2; keys live in gui-native)",
            abi::hex_encode(calldata)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsigned_sender_reports_missing_signer_honestly() {
        let err = UnsignedHeartbeatSender
            .send_heartbeat(&heartbeat::heartbeat_calldata())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no signer configured"), "msg was: {msg}");
        // It still carries the exact calldata it WOULD have broadcast.
        assert!(msg.contains("3defb962"), "msg was: {msg}");
    }
}
