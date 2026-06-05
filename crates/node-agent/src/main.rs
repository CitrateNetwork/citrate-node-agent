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

mod bridge;
mod clock;
mod daemon;
mod live;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bidder::{BidDecision, ComputePricingOracle, Settings};
use chainio::abi;
use config::ComputeSettings;
use tokio::sync::RwLock;

/// Default per-job work estimate used until the executor's profiler lands (S2):
/// 0.5 pflop-hours (×1e18) and a 5-minute typical execution time. These are the
/// agent's own estimates, not chain data; they feed cost-plus pricing and the
/// deadline-feasibility gate.
const DEFAULT_PFLOP_HOURS_1E18: u128 = 500_000_000_000_000_000; // 0.5 ×1e18
const DEFAULT_EXEC_SECS: u64 = 300;

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

    let client = chainio::rpc::RpcClient::new(rpc_url);
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

    let bid_job = bridge::map_job(
        &job,
        current_block,
        DEFAULT_PFLOP_HOURS_1E18,
        DEFAULT_EXEC_SECS,
    );

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
    println!("node-agent daemon: supervision on http://{addr} (/health /status /pause /resume)");
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        if let Err(e) = supervision::serve(addr, server_state).await {
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
            let client = chainio::rpc::RpcClient::new(rpc_url);
            let chain_id = client.eth_chain_id().await?;
            if chain_id != chainio::CHAIN_ID {
                return Err(format!(
                    "connected chain id {chain_id} != expected {}",
                    chainio::CHAIN_ID
                )
                .into());
            }
            let view = live::LiveMarketView {
                client,
                marketplace: abi::address_from_hex(chainio::compute_marketplace())?,
                oracle: abi::address_from_hex(chainio::compute_pricing_oracle())?,
                provider: abi::address_from_hex(&provider_hex)?,
                job_id,
                estimated_pflop_hours_1e18: DEFAULT_PFLOP_HOURS_1E18,
                estimated_exec_secs: DEFAULT_EXEC_SECS,
            };
            let sender = live::UnsignedHeartbeatSender;
            println!("node-agent daemon: live loop on chain {chain_id}, job #{job_id}");
            daemon::run_loop(
                state,
                &view,
                &sender,
                &bid_settings,
                heartbeat::HEARTBEAT_INTERVAL,
                None,
            )
            .await;
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
