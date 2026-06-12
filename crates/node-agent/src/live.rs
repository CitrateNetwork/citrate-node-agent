//! `live` — production wiring for the daemon loop: real chain reads behind the
//! [`crate::daemon::MarketView`] trait, and the honest heartbeat sender.
//!
//! These are the real I/O implementations the binary uses when
//! `CITRATE_RPC_URL` + `CITRATE_PROVIDER_ADDRESS` are configured. They contain
//! no stub logic: every read is a real `eth_call`, and the heartbeat sender
//! tells the truth about the one capability the agent does not yet own — signing
//! (keys live in gui-native's keystore, broadcast lands in SELL-S2). It returns
//! an explicit error rather than faking a successful broadcast.

use std::path::PathBuf;

use bidder::{Caps, ComputePricingOracle};
use chainio::abi::{self, Address};
use chainio::rpc::RpcClient;
use heartbeat::{HeartbeatError, HeartbeatSender};

use crate::bridge;
use crate::daemon::{MarketSnapshot, MarketView};
use crate::execution::{ClaimableView, InputSource, JobView, ResolvedJob};

/// Real chain reads for one provider + one target job id.
pub struct LiveMarketView {
    pub client: RpcClient,
    pub marketplace: Address,
    pub oracle: Address,
    pub provider: Address,
    pub job_id: u128,
    /// Per-model work estimates from the executor's real runs (TD-10).
    pub profiler: std::sync::Arc<crate::profiler::ModelProfiler>,
    /// Chain-derived seconds-per-block for the deadline conversion (TD-10).
    pub secs_per_block: u64,
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
        // Per-model work estimate from real runs (defaults until first profiled).
        let (pflop_hours, exec_secs) = self.profiler.estimate(&chain_job.model_hash);
        let job = bridge::map_job(
            &chain_job,
            current_block,
            self.secs_per_block,
            pflop_hours,
            exec_secs,
        );

        Ok(MarketSnapshot {
            caps,
            reputation_bps: profile.reputation_score_bps as u32,
            stake_wei: profile.stake_wei,
            job,
            oracle,
        })
    }
}

/// Real `JobView`: resolves a job id via `getJob` + `getModel` + `eth_blockNumber`.
///
/// `expected_size` is `None` — `ModelRegistry.getModel` does not return
/// `sizeBytes` (TD-26); supply a size only if a richer read is wired later.
///
/// SECREM-01 SVC-2 (pre-audit 2026-06-09): `weights_sha256` is the operator's
/// trusted digest of the model weights (`CITRATE_MODEL_SHA256`); the registry
/// does not expose one (TD). When `None`, provisioning only succeeds for
/// self-verifying CIDv1 raw sha2-256 CIDs and otherwise fails closed — the
/// gateway is never trusted for integrity.
pub struct LiveJobView {
    pub client: RpcClient,
    pub marketplace: Address,
    pub model_registry: Address,
    pub verifier: Address,
    pub weights_sha256: Option<[u8; 32]>,
}

impl JobView for LiveJobView {
    async fn resolve(&self, job_id: u128) -> Result<ResolvedJob, String> {
        let job = chainio::marketplace::live::get_job(&self.client, self.marketplace, job_id)
            .await
            .map_err(|e| format!("getJob: {e}"))?;
        let model =
            chainio::model_registry::live::get_model(&self.client, self.model_registry, job.model_hash)
                .await
                .map_err(|e| format!("getModel: {e}"))?;
        let current_block = self
            .client
            .eth_block_number()
            .await
            .map_err(|e| format!("blockNumber: {e}"))?;
        // Chain truth: has the commitment been recorded? Gates submitResult.
        let committed =
            chainio::verifier::live::commitment_submitted(&self.client, self.verifier, job_id)
                .await
                .map_err(|e| format!("getRecord: {e}"))?;
        Ok(ResolvedJob {
            job,
            ipfs_cid: model.ipfs_cid,
            is_active: model.is_active,
            expected_size: None,
            expected_sha256: self.weights_sha256, // SECREM-01 SVC-2
            current_block,
            committed,
        })
    }
}

/// Off-chain input channel as a watched directory: the requester / gateway drops
/// the job input at `<dir>/<job_id>.bin`. `Job.inputHash` is only a hash, so this
/// is the real delivery seam (a richer transport — gateway push, libp2p — can
/// replace it behind the same `InputSource` trait). Returns `None` until the file
/// appears (the executor holds and retries).
pub struct FileInputSource {
    pub dir: PathBuf,
}

impl InputSource for FileInputSource {
    async fn input_for(&self, job_id: u128) -> Result<Option<Vec<u8>>, String> {
        let path = self.dir.join(format!("{job_id}.bin"));
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }
}

/// Real `ClaimableView`: reads `ContributionAccounting.claimable(me)`.
pub struct LiveClaimableView {
    pub client: RpcClient,
    pub accounting: Address,
    pub me: Address,
}

impl ClaimableView for LiveClaimableView {
    async fn claimable(&self) -> Result<u128, String> {
        chainio::accounting::live::claimable(&self.client, self.accounting, self.me)
            .await
            .map_err(|e| format!("claimable: {e}"))
    }
}

/// A 32-byte unpredictable commitment nonce from the OS RNG (`/dev/urandom`).
/// The Commitment scheme needs the nonce to be unpredictable before the output
/// is revealed.
pub fn random_nonce() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf)
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(buf)
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
