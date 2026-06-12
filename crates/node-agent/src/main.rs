//! `node-agent` — the Citrate node agent binary (SELL-S1 slice).
//!
//! This is a real, minimal orchestration entry point that ties the pieces built
//! in S1 together:
//!   1. read `compute.json` ([`config`]),
//!   2. sample the clock ([`clock`]) for the schedule gate,
//!   3. (if `CITRATE_RPC_URL` is set) read the live chain — chain id, the
//!      pricing oracle, the provider profile, and a target job — via the
//!      [`chainio`] JSON-RPC client,
//!   4. run the pure cost-plus [`bidder`] to produce a [`bidder::BidDecision`],
//!   5. report the decision and the heartbeat calldata it would broadcast.
//!
//! It does **not** sign or broadcast transactions (the gui-native keystore owns
//! keys); S1 is the read/decide slice. There is no stub logic: every branch
//! either does real work or honestly reports what is missing (e.g. no RPC URL →
//! config self-check only).
//!
//! Usage:
//!   node-agent <path-to-compute.json> [job-id]
//! Env:
//!   CITRATE_RPC_URL   chain-40204 JSON-RPC endpoint (enables live reads)
//!
//! Outbound TLS (FUA-NODE-AGENT-06, SECREM-02 WP 7.4): every outbound endpoint
//! (`CITRATE_RPC_URL`, `CITRATE_IPFS_GATEWAY`, `CITRATE_LLAMA_URL`) must be
//! `https://`, or plain `http://` to a **loopback** host only; anything else is
//! refused at startup. `CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1` is a
//! **dev-only** escape hatch for plaintext LAN rigs — never set in production.

mod bridge;
mod clock;
mod daemon;
// SELL-S2 job-execution orchestration: drives a won job
// provision→infer→prove→submit→complete via the unsigned JobSigner seam. Wired
// into the daemon loop below (`build_job_executor` → `run_loop`'s executor). The
// remaining external pieces — the off-chain input transport beyond a watched
// directory, and the signing/broadcast *relay* — are the TD-27/TD-17 follow-ups.
mod execution;
mod live;
mod profiler;
mod relay;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bidder::{BidDecision, ComputePricingOracle, Settings};
use chainio::abi;
use config::ComputeSettings;
use tokio::sync::RwLock;

/// Fallback per-model execution-time estimate (seconds) before a model has been
/// profiled from a real run (TD-10). Feeds the deadline-feasibility gate.
const DEFAULT_EXEC_SECS: u64 = 300;
/// Default node throughput (pflops ×1e18) used to derive pflop-hours from the
/// measured/estimated execution time. 6 pflops × (300s/3600) = 0.5 pflop-hours,
/// reproducing the old SELL-S1 default for an unprofiled node. Override with
/// `CITRATE_NODE_PFLOPS_1E18`.
const DEFAULT_NODE_PFLOPS_1E18: u128 = 6_000_000_000_000_000_000;
/// Blocks to sample when deriving seconds-per-block from chain timestamps.
const SECS_PER_BLOCK_SAMPLE: u128 = 20;

/// Build the per-model profiler from config (the node's throughput).
fn build_profiler() -> std::sync::Arc<profiler::ModelProfiler> {
    let node_pflops = std::env::var("CITRATE_NODE_PFLOPS_1E18")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NODE_PFLOPS_1E18);
    std::sync::Arc::new(profiler::ModelProfiler::new(node_pflops, DEFAULT_EXEC_SECS))
}

/// Derive seconds-per-block from chain timestamps, falling back to the default
/// when it can't be sampled (idle devnet / too few blocks).
async fn derive_secs_per_block(client: &chainio::rpc::RpcClient) -> u64 {
    match client.secs_per_block(SECS_PER_BLOCK_SAMPLE).await {
        Ok(Some(s)) => s,
        _ => bridge::DEFAULT_SECS_PER_BLOCK,
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("node-agent: error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Collect args, splitting off a leading/embedded `--daemon` flag. Daemon mode
    // can also be requested via env (`CITRATE_NODE_AGENT_DAEMON=1`) so the GUI can
    // launch it without crafting argv.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let flag_daemon = raw.iter().any(|a| a == "--daemon");
    let env_daemon = matches!(
        std::env::var("CITRATE_NODE_AGENT_DAEMON").ok().as_deref(),
        Some("1") | Some("true")
    );
    let daemon_mode = flag_daemon || env_daemon;
    let mut positional = raw.into_iter().filter(|a| a != "--daemon");

    let config_path = positional.next().ok_or(
        "usage: node-agent [--daemon] <path-to-compute.json> [job-id]   (env: CITRATE_RPC_URL)",
    )?;
    let job_id: u128 = match positional.next() {
        Some(s) => s.parse().map_err(|_| "job-id must be a non-negative integer")?,
        None => 0,
    };

    if daemon_mode {
        return run_daemon(&config_path, job_id).await;
    }

    // 1. Config.
    let raw = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("reading {config_path}: {e}"))?;
    let settings = ComputeSettings::from_json(&raw)?;
    println!(
        "compute.json: enabled={} allocation={}% schedule={:?}",
        settings.enabled, settings.allocation_percent, settings.schedule
    );

    // 2. Clock → schedule context (UTC for S1).
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (hour, weekday) = clock::utc_hour_and_weekday(now);
    println!("clock (UTC): hour={hour} weekday={weekday:?}");

    let bid_settings = Settings {
        enabled: settings.enabled,
        schedule: settings.schedule,
        current_hour: hour,
        current_day: weekday,
    };

    // The heartbeat calldata the agent would broadcast every 30s to stay live.
    println!(
        "heartbeat calldata: {}",
        abi::hex_encode(&heartbeat::heartbeat_calldata())
    );

    // 3. Live chain reads (only if an RPC endpoint is configured).
    let rpc_url = std::env::var("CITRATE_RPC_URL").ok();
    let Some(rpc_url) = rpc_url else {
        println!(
            "CITRATE_RPC_URL not set — config self-check only (no live reads). \
             Marketplace={} Oracle={}",
            chainio::compute_marketplace(),
            chainio::compute_pricing_oracle(),
        );
        return Ok(());
    };

    let client = chainio::rpc::RpcClient::new(rpc_url)?; // FUA-NODE-AGENT-06: https or loopback only
    let chain_id = client.eth_chain_id().await?;
    if chain_id != chainio::CHAIN_ID {
        return Err(format!(
            "connected chain id {chain_id} != expected {}",
            chainio::CHAIN_ID
        )
        .into());
    }
    println!("connected to chain id {chain_id}");

    let marketplace = abi::address_from_hex(chainio::compute_marketplace())?;
    let oracle_addr = abi::address_from_hex(chainio::compute_pricing_oracle())?;

    // Oracle price + staleness for cost-plus pricing.
    let salt_per_pflop_hour =
        chainio::marketplace::live::salt_per_pflop_hour(&client, oracle_addr).await?;
    let stale = chainio::marketplace::live::is_price_stale(&client, oracle_addr).await?;
    let oracle = ComputePricingOracle {
        salt_per_pflop_hour_wei: salt_per_pflop_hour,
        stale,
    };
    println!("oracle: saltPerPflopHour={salt_per_pflop_hour} wei stale={stale}");

    // Provider profile (capacity) — the agent's own wallet, if provided.
    let caps = match std::env::var("CITRATE_PROVIDER_ADDRESS").ok() {
        Some(addr_hex) => {
            let provider = abi::address_from_hex(&addr_hex)?;
            let profile =
                chainio::marketplace::live::get_provider(&client, marketplace, provider).await?;
            println!(
                "provider: registered={} active={}/{} reputation={}bps",
                profile.is_registered,
                profile.current_active_jobs,
                profile.max_concurrent_jobs,
                profile.reputation_score_bps
            );
            bridge::map_caps(&profile)
        }
        None => {
            // No provider address configured: assume a fresh, idle, default-cap
            // provider so the bidder can still demonstrate a decision.
            bidder::Caps {
                current_active_jobs: 0,
                max_concurrent_jobs: 10,
            }
        }
    };

    // Target job + current block.
    let job = chainio::marketplace::live::get_job(&client, marketplace, job_id).await?;
    let current_block = client.eth_block_number().await?;
    println!(
        "job #{}: maxPrice={} wei tier={:?} state={:?} execDeadline={} (block {})",
        job.id, job.max_price_wei, job.tier, job.state, job.execution_deadline_block, current_block
    );

    // Chain-derived block time + per-model estimate (defaults until profiled).
    let secs_per_block = derive_secs_per_block(&client).await;
    let (pflop_hours, exec_secs) = build_profiler().estimate(&job.model_hash);
    let bid_job = bridge::map_job(&job, current_block, secs_per_block, pflop_hours, exec_secs);

    // 4. Decision.
    let decision = bidder::evaluate(&bid_job, &oracle, &bid_settings, &caps);
    match decision {
        BidDecision::Bid {
            job_id,
            price_wei,
            estimated_cost_wei,
        } => {
            println!(
                "DECISION: BID on job #{job_id} at {price_wei} wei (cost {estimated_cost_wei} wei)"
            );
            println!(
                "  would broadcast bidOnJob calldata: {}",
                abi::hex_encode(&chainio::marketplace::encode_bid_on_job(
                    job_id as u128,
                    price_wei,
                    (DEFAULT_EXEC_SECS as u128) * 1000
                ))
            );
        }
        BidDecision::Skip { job_id, reason } => {
            println!("DECISION: SKIP job #{job_id} — {}", reason.as_str());
        }
    }

    Ok(())
}

/// Daemon mode: bring up the supervision HTTP surface and run the supervised
/// loop. The loop refreshes the chain view, runs the bidder, records state, and
/// sends heartbeats on the heartbeat cadence — respecting `/pause`. No real job
/// execution yet (SELL-S2); the state machine + supervision are real.
async fn run_daemon(config_path: &str, job_id: u128) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Config → bidder settings (sampled clock for the schedule gate).
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| format!("reading {config_path}: {e}"))?;
    let settings = ComputeSettings::from_json(&raw)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (hour, weekday) = clock::utc_hour_and_weekday(now);
    let bid_settings = Settings {
        enabled: settings.enabled,
        schedule: settings.schedule,
        current_hour: hour,
        current_day: weekday,
    };

    // 2. Shared state + supervision server (loopback only).
    let state: supervision::SharedState = Arc::new(RwLock::new(supervision::AgentState::new()));
    let addr = supervision::resolve_addr()?;
    // Per-instance bearer token (FUA-NODE-AGENT-01/02): mint or load it, persisted
    // 0600, and require it on every endpoint except /health. gui-native reads the
    // same file (CITRATE_NODE_AGENT_TOKEN_FILE) and presents the token.
    let token_path = supervision::default_token_path();
    let auth = supervision::SupervisionAuth::load_or_create(&token_path)
        .map_err(|e| format!("supervision token at {}: {e}", token_path.display()))?;
    println!(
        "node-agent daemon: supervision on http://{addr} (/health open; bearer token at {})",
        token_path.display()
    );
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        if let Err(e) = supervision::serve(addr, server_state, auth).await {
            eprintln!("node-agent: supervision server stopped: {e}");
        }
    });

    // 3. Live chain view (when fully configured) drives the loop. Without an RPC
    //    URL + provider address there is no real market to read, so the daemon
    //    serves supervision in a self-check posture and reports it honestly
    //    rather than fabricating reads.
    let rpc_url = std::env::var("CITRATE_RPC_URL").ok();
    let provider_addr = std::env::var("CITRATE_PROVIDER_ADDRESS").ok();
    match (rpc_url, provider_addr) {
        (Some(rpc_url), Some(provider_hex)) => {
            let client = chainio::rpc::RpcClient::new(rpc_url.clone())?; // FUA-NODE-AGENT-06: https or loopback only
            let chain_id = client.eth_chain_id().await?;
            if chain_id != chainio::CHAIN_ID {
                return Err(format!(
                    "connected chain id {chain_id} != expected {}",
                    chainio::CHAIN_ID
                )
                .into());
            }
            let marketplace = abi::address_from_hex(chainio::compute_marketplace())?;
            let model_registry = abi::address_from_hex(chainio::model_registry())?;
            let provider = abi::address_from_hex(&provider_hex)?;

            // TD-10: chain-derived block time + per-model profiler (shared between
            // the bidder's market view and the executor that records real runs).
            let secs_per_block = derive_secs_per_block(&client).await;
            let profiler = build_profiler();
            println!("node-agent daemon: block time {secs_per_block}s/block (chain-derived)");

            let view = live::LiveMarketView {
                client,
                marketplace,
                oracle: abi::address_from_hex(chainio::compute_pricing_oracle())?,
                provider,
                job_id,
                profiler: profiler.clone(),
                secs_per_block,
            };
            // Liveness + bids go through the signing relay like every other
            // write (ADR-agent-signing): heartbeat() re-arms each beat;
            // bidOnJob is enqueued when the bidder decides to bid.
            let sender = relay::RelayHeartbeatSender::new(
                state.clone(),
                abi::address_from_hex(chainio::heartbeat_monitor())?,
                chain_id,
            );
            let bid_placer = relay::RelayBidPlacer::new(state.clone(), marketplace, chain_id);

            // The signing relay: unsigned writes are enqueued into the shared
            // supervision state for gui-native to sign + broadcast + observe.
            let signer = relay::RelaySigner::new(state.clone());

            // Earnings polling runs whenever RPC + provider are configured (a
            // provider earns from past jobs even when not currently executing).
            let accounting = abi::address_from_hex(chainio::contribution_accounting())?;
            let claim_threshold_wei = std::env::var("CITRATE_CLAIM_THRESHOLD_WEI")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_000_000_000_000_000_000u128); // 1 SALT
            let earnings = execution::EarningsPoller {
                cfg: earnings::EarningsConfig {
                    threshold_wei: claim_threshold_wei,
                    accounting,
                    chain_id,
                },
                view: live::LiveClaimableView {
                    client: chainio::rpc::RpcClient::new(rpc_url.clone())?,
                    accounting,
                    me: provider,
                },
                signer: signer.clone(),
                in_flight: tokio::sync::Mutex::new(false),
            };

            // SELL-S2 execution wiring: drive the configured job when the
            // execution backends are all configured; otherwise bid + earn only.
            match build_job_executor(&rpc_url, marketplace, model_registry, provider, job_id, chain_id, signer, profiler.clone())? {
                Some(exec) => {
                    println!(
                        "node-agent daemon: live loop on chain {chain_id}, job #{job_id} — \
                         EXECUTION + earnings enabled; unsigned writes are queued to \
                         GET /signature-requests for gui-native to sign + broadcast + observe \
                         (POST /signature-requests/{{id}}/observed)"
                    );
                    daemon::run_loop(
                        state,
                        &view,
                        &sender,
                        &execution::Both(exec, earnings),
                        &bid_placer,
                        &bid_settings,
                        heartbeat::HEARTBEAT_INTERVAL,
                        None,
                    )
                    .await;
                }
                None => {
                    println!(
                        "node-agent daemon: live loop on chain {chain_id}, job #{job_id} — \
                         bid + earnings (execution off; set CITRATE_IPFS_GATEWAY + \
                         CITRATE_LLAMA_URL + CITRATE_JOB_INPUT_DIR to execute won jobs)"
                    );
                    daemon::run_loop(
                        state,
                        &view,
                        &sender,
                        &earnings,
                        &bid_placer,
                        &bid_settings,
                        heartbeat::HEARTBEAT_INTERVAL,
                        None,
                    )
                    .await;
                }
            }
        }
        _ => {
            println!(
                "node-agent daemon: CITRATE_RPC_URL/CITRATE_PROVIDER_ADDRESS not both set — \
                 supervision-only self-check (no live market reads). Set both to run the live loop."
            );
            // Keep the supervision surface alive so the GUI can still observe/pause.
            state.write().await.set_last_error(Some(
                "live loop disabled: set CITRATE_RPC_URL + CITRATE_PROVIDER_ADDRESS".into(),
            ));
            server.await.ok();
        }
    }

    Ok(())
}

/// The concrete live SELL-S2 executor: live chain reads + watched-dir input +
/// IPFS-gateway weights + resident llama-server inference + the unsigned signer.
type LiveJobExecutor = execution::JobExecutor<
    live::LiveJobView,
    live::FileInputSource,
    executor::IpfsGatewaySource,
    executor::LlamaServerInference,
    relay::RelaySigner,
>;

/// Build the live job executor if the execution backends are configured, else
/// `None` (bid-only). Requires `CITRATE_IPFS_GATEWAY` (weights), `CITRATE_LLAMA_URL`
/// (inference), and `CITRATE_JOB_INPUT_DIR` (the off-chain input drop); the model
/// cache dir defaults but can be overridden with `CITRATE_MODEL_CACHE_DIR`.
#[allow(clippy::too_many_arguments)] // distinct chain/exec params; bundling adds noise
fn build_job_executor(
    rpc_url: &str,
    marketplace: chainio::abi::Address,
    model_registry: chainio::abi::Address,
    me: chainio::abi::Address,
    job_id: u128,
    chain_id: u64,
    signer: relay::RelaySigner,
    profiler: std::sync::Arc<profiler::ModelProfiler>,
) -> Result<Option<LiveJobExecutor>, Box<dyn std::error::Error>> {
    let (Some(gateway), Some(llama), Some(input_dir)) = (
        std::env::var("CITRATE_IPFS_GATEWAY").ok(),
        std::env::var("CITRATE_LLAMA_URL").ok(),
        std::env::var("CITRATE_JOB_INPUT_DIR").ok(),
    ) else {
        return Ok(None);
    };
    let cache_dir = std::env::var("CITRATE_MODEL_CACHE_DIR")
        .unwrap_or_else(|_| "/var/lib/citrate-node-agent/models".to_string());
    // SECREM-01 SVC-2 (pre-audit 2026-06-09): operator-supplied trusted sha-256
    // of the model weights (`CITRATE_MODEL_SHA256`, 64 hex chars, optional 0x).
    // Without it, provisioning succeeds only for self-verifying CIDv1 raw
    // sha2-256 CIDs and otherwise fails closed — weight integrity is recomputed
    // locally, never trusted from the IPFS gateway.
    let weights_sha256 = match std::env::var("CITRATE_MODEL_SHA256").ok() {
        Some(h) => Some(
            parse_sha256_hex(&h)
                .ok_or("CITRATE_MODEL_SHA256 must be 64 hex chars (optional 0x prefix)")?,
        ),
        None => None,
    };
    let nonce = live::random_nonce()?;

    Ok(Some(execution::JobExecutor {
        job_id,
        me,
        marketplace,
        chain_id,
        cache_dir: cache_dir.into(),
        nonce,
        view: live::LiveJobView {
            client: chainio::rpc::RpcClient::new(rpc_url.to_string())?,
            marketplace,
            model_registry,
            verifier: chainio::abi::address_from_hex(chainio::compute_verifier())?,
            weights_sha256, // SECREM-01 SVC-2
        },
        input: live::FileInputSource {
            dir: input_dir.into(),
        },
        weights: executor::IpfsGatewaySource::new(gateway)?, // FUA-NODE-AGENT-06
        inference: executor::LlamaServerInference::new(llama)?, // FUA-NODE-AGENT-06
        signer,
        profiler,
        progress: tokio::sync::Mutex::new(execution::JobProgress::default()),
    }))
}

/// Parse a 32-byte sha-256 from hex (optional `0x` prefix). SECREM-01 SVC-2.
fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
