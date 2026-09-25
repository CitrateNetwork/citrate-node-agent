//! `daemon` — the supervised run loop that turns the one-shot agent into a
//! long-lived daemon.
//!
//! Responsibilities each tick:
//!   1. refresh the chain view (provider stats, target job, oracle) via a
//!      [`MarketView`] (live RPC in production, a test double in unit tests),
//!   2. push provider capacity/reputation into the shared [`AgentState`],
//!   3. unless paused, run the pure [`bidder::evaluate`] and record whether the
//!      tick is bidding/idle,
//!   4. send a heartbeat on the heartbeat cadence via a [`HeartbeatSender`].
//!
//! The state machine + supervision endpoints are the real deliverable; **no
//! real job execution happens yet** (that is SELL-S2). In-flight jobs are
//! represented only by the `active_jobs` count the executor will later drive.
//!
//! Pause semantics: when `/pause` has set the shared state to paused,
//! [`AgentState::accepts_new_bids`] is false, so step (3) is skipped entirely —
//! no NEW bid is evaluated — while heartbeats (step 4) and chain refreshes
//! (steps 1–2) continue so the provider stays live and the GUI keeps observing.
//! Any in-flight `active_jobs` are untouched (they finish).

use std::time::Duration;

use bidder::{BidDecision, Caps, ComputePricingOracle, Job as BidJob, Settings};
use heartbeat::{HeartbeatError, HeartbeatSender};
use supervision::SharedState;

use crate::execution::TickExecutor;

/// One refreshed view of the market the loop needs to make a decision: the
/// agent's provider stats, the target job, and the oracle reading.
///
/// Production wires this from `chainio` live reads; tests provide a fixed view.
#[derive(Debug, Clone)]
pub struct MarketSnapshot {
    /// Provider capacity (active vs. max concurrent).
    pub caps: Caps,
    /// Provider reputation in basis points (from `getProvider`).
    pub reputation_bps: u32,
    /// Provider stake in wei (from `getProvider`) — feeds the slash detector.
    pub stake_wei: u128,
    /// The job under consideration this tick.
    pub job: BidJob,
    /// The pricing oracle reading.
    pub oracle: ComputePricingOracle,
    /// PBA-L6b-025: `Some(bid_deadline_block)` while the job is open for bids
    /// (state Posted/Bidding and the bid deadline not yet reached); `None`
    /// otherwise. A bid is only placed when `Some`, and the unsigned write
    /// carries this block as its `expires_block`.
    pub bid_expires_block: Option<u128>,
}

/// Source of [`MarketSnapshot`]s. Async so the live implementation can do RPC.
pub trait MarketView {
    /// Refresh the market view for this tick.
    fn refresh(
        &self,
    ) -> impl std::future::Future<Output = Result<MarketSnapshot, String>> + Send;
}

/// Places the bid the bidder decided (SELL-S1: deciding is not bidding — the
/// write must reach the chain to be won). The production implementation
/// enqueues an unsigned `bidOnJob` for the signing relay; tests use a
/// recording fake; [`NoBids`] is the explicit no-op for bid-less loops.
pub trait BidPlacer {
    /// Request the `bidOnJob(job_id, price_wei, estimated_latency_ms)` write,
    /// valid until `expires_block` (the job's bid deadline — PBA-L6b-025).
    fn place(
        &self,
        job_id: u128,
        price_wei: u128,
        estimated_latency_ms: u128,
        expires_block: u128,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Explicit no-op placer for tests that only assert decisions. Test-only —
/// every production loop places bids through the relay.
#[cfg(test)]
pub struct NoBids;

#[cfg(test)]
impl BidPlacer for NoBids {
    async fn place(&self, _: u128, _: u128, _: u128, _: u128) -> Result<(), String> {
        Ok(())
    }
}

/// The decision recorded for one tick (for tests + logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// Paused: no new bid was evaluated.
    SkippedPaused,
    /// Evaluated and decided to bid.
    Bid,
    /// Evaluated and decided to skip (with the bidder's decision carried).
    NoBid,
    /// The market refresh failed; the tick recorded the error and moved on.
    RefreshError,
}

/// Run a single tick of the loop against the shared state.
///
/// This is the pure-ish core (no sleeping, no real clock for cadence): it
/// refreshes the market, updates provider stats, and — unless paused — runs the
/// bidder and records bidding/idle. Returns what happened so the caller/tests
/// can assert. Heartbeat sending is handled by the surrounding loop on its own
/// cadence, not here.
pub async fn tick<V: MarketView, B: BidPlacer>(
    state: &SharedState,
    view: &V,
    settings: &Settings,
    bids: &B,
) -> TickOutcome {
    // 1–2. Refresh the chain view and push provider stats into shared state.
    let snapshot = match view.refresh().await {
        Ok(s) => s,
        Err(e) => {
            let mut w = state.write().await;
            w.set_last_error(Some(format!("market refresh failed: {e}")));
            w.set_idle();
            return TickOutcome::RefreshError;
        }
    };

    {
        let mut w = state.write().await;
        // Full observation: also runs the slash + reputation-drop detectors
        // (SELL-S1 alerts; latched in /health.alert).
        w.record_provider_observation(
            snapshot.caps.max_concurrent_jobs as u32,
            snapshot.reputation_bps,
            snapshot.stake_wei,
        );
        // A successful refresh clears any prior transient error.
        w.set_last_error(None);
    }

    // 3. Respect pause: do not evaluate NEW bids while paused.
    if !state.read().await.accepts_new_bids() {
        return TickOutcome::SkippedPaused;
    }

    // PBA-L6b-025: only a job that is open for bids (Posted/Bidding, before its
    // bid deadline) may be bid on; the bid expires at that deadline.
    let Some(expires_block) = snapshot.bid_expires_block else {
        state.write().await.set_idle();
        return TickOutcome::NoBid;
    };

    // Run the pure bidder and record the resulting tick state.
    let decision = bidder::evaluate(&snapshot.job, &snapshot.oracle, settings, &snapshot.caps);
    match decision {
        BidDecision::Bid {
            job_id, price_wei, ..
        } => {
            // Deciding is not bidding: hand the write to the placer so it
            // actually reaches the chain (via the signing relay). The
            // estimated-latency arg mirrors the one-shot path: exec estimate
            // in milliseconds.
            let latency_ms = u128::from(snapshot.job.estimated_exec_secs) * 1000;
            let placed = bids
                .place(u128::from(job_id), price_wei, latency_ms, expires_block)
                .await;
            let mut w = state.write().await;
            if let Err(e) = placed {
                w.set_last_error(Some(format!("bid placement failed: {e}")));
            }
            w.set_bidding(true);
            TickOutcome::Bid
        }
        BidDecision::Skip { .. } => {
            state.write().await.set_idle();
            TickOutcome::NoBid
        }
    }
}

/// Send a heartbeat and record it (or its failure) in the shared state. Returns
/// the send result so the caller can decide whether to keep looping (it always
/// should — a transient blip must not kill liveness).
pub async fn beat<S: HeartbeatSender>(
    state: &SharedState,
    sender: &S,
) -> Result<heartbeat::SendOutcome, HeartbeatError> {
    let calldata = heartbeat::heartbeat_calldata();
    let res = sender.send_heartbeat(&calldata).await;
    let mut w = state.write().await;
    match &res {
        // Only a real broadcast is liveness. A QUEUED beat is recorded when
        // the signing surface reports it observed (supervision does that on
        // the observe callback) — /health.heartbeat_age never lies.
        Ok(heartbeat::SendOutcome::Broadcast) => {
            w.record_heartbeat();
        }
        Ok(heartbeat::SendOutcome::Queued) => {}
        Err(e) => {
            w.set_last_error(Some(e.to_string()));
        }
    }
    res
}

/// Where the loop gets the bidder [`Settings`] for a tick (PBA-L6b-008).
///
/// The schedule / window-close gates compare against the *current* clock, and
/// the operator may flip `compute.json` (enabled, schedule) while the daemon
/// runs, so the loop asks for fresh settings on every tick instead of sampling
/// them once at startup.
pub trait SettingsSource {
    /// The settings to evaluate this tick against.
    fn current(&self) -> Result<Settings, String>;
}

/// A fixed [`Settings`] value (tests, one-shot embedders): never changes.
impl SettingsSource for Settings {
    fn current(&self) -> Result<Settings, String> {
        Ok(*self)
    }
}

/// Production settings: re-read `compute.json` and re-sample the clock on every
/// call. `now` returns UNIX seconds (injectable for virtual-time tests).
pub struct LiveSettings<C: Fn() -> u64> {
    /// Path to the operator's `compute.json`.
    pub config_path: std::path::PathBuf,
    /// Clock: UNIX seconds.
    pub now: C,
}

impl<C: Fn() -> u64> SettingsSource for LiveSettings<C> {
    fn current(&self) -> Result<Settings, String> {
        let raw = std::fs::read_to_string(&self.config_path)
            .map_err(|e| format!("reading {}: {e}", self.config_path.display()))?;
        let cfg = config::ComputeSettings::from_json(&raw)
            .map_err(|e| format!("parsing {}: {e}", self.config_path.display()))?;
        let (hour, minute, weekday) = crate::clock::utc_hour_min_weekday((self.now)());
        Ok(Settings {
            enabled: cfg.enabled,
            schedule: cfg.schedule,
            current_hour: hour,
            current_min: minute,
            current_day: weekday,
        })
    }
}

/// Fail-closed settings for a tick whose `compute.json` could not be read or
/// parsed: participation off, so no bid goes out on stale or unknown policy.
fn disabled_settings() -> Settings {
    Settings {
        enabled: false,
        schedule: config::Schedule::Always,
        current_hour: 0,
        current_min: 0,
        current_day: config::Weekday::Mon,
    }
}

/// Resolve the settings for one tick: the source's answer, or fail-closed
/// [`disabled_settings`] plus the error to record.
fn settings_for_tick<P: SettingsSource>(source: &P) -> (Settings, Option<String>) {
    match source.current() {
        Ok(s) => (s, None),
        Err(e) => (
            disabled_settings(),
            Some(format!("settings reload failed (not bidding): {e}")),
        ),
    }
}

/// Run the supervised loop until `max_ticks` ticks have run (`None` = forever).
///
/// Each tick runs [`tick`] (bid), then the [`TickExecutor`] (drive a won job —
/// `NoExecutor` for the bid-only loop), then [`beat`] (the heartbeat cadence is
/// one beat per tick here; in production the tick interval *is* the heartbeat
/// interval). The loop never returns on a heartbeat error — it records it and
/// keeps going.
#[allow(clippy::too_many_arguments)]
pub async fn run_loop<V, S, E, B, P>(
    state: SharedState,
    view: &V,
    sender: &S,
    executor: &E,
    bids: &B,
    settings: &P,
    interval: Duration,
    max_ticks: Option<u64>,
) where
    V: MarketView,
    S: HeartbeatSender,
    E: TickExecutor,
    B: BidPlacer,
    P: SettingsSource,
{
    let mut ticks: u64 = 0;
    loop {
        if let Some(max) = max_ticks {
            if ticks >= max {
                return;
            }
        }
        // PBA-L6b-008: re-sample the clock and re-read compute.json every tick.
        let (settings_now, settings_err) = settings_for_tick(settings);
        tick(&state, view, &settings_now, bids).await;
        if let Some(e) = &settings_err {
            state.write().await.set_last_error(Some(e.clone()));
        }
        executor.tick(&state).await; // drive a won job (no-op in the bid-only loop)
        let _ = beat(&state, sender).await; // errors are recorded, never fatal
        ticks += 1;
        if let Some(max) = max_ticks {
            if ticks >= max {
                return;
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use bidder::VerificationTier;
    use config::{Schedule, Weekday};
    use supervision::AgentState;
    use tokio::sync::RwLock;

    fn shared() -> SharedState {
        Arc::new(RwLock::new(AgentState::new()))
    }

    fn on_settings() -> Settings {
        Settings {
            enabled: true,
            schedule: Schedule::Always,
            current_hour: 12,
            current_min: 0,
            current_day: Weekday::Wed,
        }
    }

    // A view that bids: 4 SALT Commitment job, roomy caps, fresh oracle.
    fn biddable_snapshot() -> MarketSnapshot {
        MarketSnapshot {
            caps: Caps {
                current_active_jobs: 0,
                max_concurrent_jobs: 10,
            },
            reputation_bps: 9230,
            stake_wei: 1000 * bidder::ONE_SALT_WEI,
            job: BidJob {
                id: 7,
                max_price_wei: 4 * bidder::ONE_SALT_WEI,
                tier: VerificationTier::Commitment,
                estimated_pflop_hours_1e18: bidder::ONE_SALT_WEI,
                estimated_exec_secs: 600,
                secs_until_deadline: 3600,
            },
            oracle: ComputePricingOracle {
                salt_per_pflop_hour_wei: bidder::ONE_SALT_WEI,
                stale: false,
            },
            bid_expires_block: Some(100),
        }
    }

    /// A fixed-snapshot view, optionally failing.
    struct FakeView {
        snapshot: MarketSnapshot,
        fail: bool,
    }
    impl MarketView for FakeView {
        async fn refresh(&self) -> Result<MarketSnapshot, String> {
            if self.fail {
                Err("simulated rpc down".into())
            } else {
                Ok(self.snapshot.clone())
            }
        }
    }

    /// A counting heartbeat sender (Send + Sync) for the loop tests.
    struct CountingSender {
        beats: Mutex<u64>,
    }
    impl HeartbeatSender for CountingSender {
        async fn send_heartbeat(
            &self,
            _calldata: &[u8],
        ) -> Result<heartbeat::SendOutcome, HeartbeatError> {
            *self.beats.lock().unwrap() += 1;
            Ok(heartbeat::SendOutcome::Broadcast)
        }
    }

    #[tokio::test]
    async fn tick_records_bidding_and_provider_stats() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let out = tick(&state, &view, &on_settings(), &NoBids).await;
        assert_eq!(out, TickOutcome::Bid);
        let h = state.read().await.health_at(0);
        assert_eq!(h.state.as_str(), "bidding");
        assert_eq!(h.max_concurrent, 10);
        assert_eq!(h.reputation_bps, 9230);
        assert_eq!(h.last_error, None);
    }

    #[tokio::test]
    async fn tick_skips_disabled_settings_to_idle() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let mut s = on_settings();
        s.enabled = false; // bidder returns Skip(Disabled)
        let out = tick(&state, &view, &s, &NoBids).await;
        assert_eq!(out, TickOutcome::NoBid);
        assert_eq!(state.read().await.health_at(0).state.as_str(), "idle");
    }

    #[tokio::test]
    async fn paused_tick_does_not_evaluate_new_bids() {
        let state = shared();
        state.write().await.pause();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let out = tick(&state, &view, &on_settings(), &NoBids).await;
        assert_eq!(out, TickOutcome::SkippedPaused);
        // Still paused, never flipped to bidding even though the job was biddable.
        assert_eq!(state.read().await.health_at(0).state.as_str(), "paused");
        // But provider stats WERE refreshed (chain reads continue while paused).
        assert_eq!(state.read().await.health_at(0).max_concurrent, 10);
    }

    #[tokio::test]
    async fn paused_lets_inflight_jobs_remain() {
        let state = shared();
        {
            let mut w = state.write().await;
            w.set_active_jobs(2); // two jobs in flight
            w.pause();
        }
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        tick(&state, &view, &on_settings(), &NoBids).await;
        // In-flight count survives the paused tick (jobs finish, not cancelled).
        assert_eq!(state.read().await.health_at(0).active_jobs, 2);
    }

    /// A view that serves a sequence of snapshots (then repeats the last one) —
    /// for delta-detection tests across ticks.
    struct SequenceView {
        snapshots: Mutex<Vec<MarketSnapshot>>,
        last: MarketSnapshot,
    }
    impl MarketView for SequenceView {
        async fn refresh(&self) -> Result<MarketSnapshot, String> {
            let mut q = self.snapshots.lock().expect("mutex not poisoned");
            if q.is_empty() {
                Ok(self.last.clone())
            } else {
                Ok(q.remove(0))
            }
        }
    }

    /// A recording bid placer (Send + Sync) for the bid-path tests.
    struct RecordingPlacer {
        placed: Mutex<Vec<(u128, u128, u128)>>,
        expires: Mutex<Vec<u128>>,
    }
    impl BidPlacer for RecordingPlacer {
        async fn place(
            &self,
            job_id: u128,
            price_wei: u128,
            latency_ms: u128,
            expires_block: u128,
        ) -> Result<(), String> {
            self.placed
                .lock()
                .expect("mutex not poisoned")
                .push((job_id, price_wei, latency_ms));
            self.expires
                .lock()
                .expect("mutex not poisoned")
                .push(expires_block);
            Ok(())
        }
    }

    /// SELL-S1: a Bid decision must actually place the bid (deciding ≠ bidding).
    #[tokio::test]
    async fn bid_decision_places_the_bid_with_cost_plus_price() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let placer = RecordingPlacer {
            placed: Mutex::new(Vec::new()),
            expires: Mutex::new(Vec::new()),
        };
        let out = tick(&state, &view, &on_settings(), &placer).await;
        assert_eq!(out, TickOutcome::Bid);
        let placed = placer.placed.lock().expect("mutex not poisoned");
        assert_eq!(placed.len(), 1, "exactly one bid placed");
        let (job_id, price_wei, latency_ms) = placed[0];
        assert_eq!(job_id, 7);
        // Cost-plus: cost = 1 PFLOP-hour × 1 SALT = 1 SALT; bid = cost × 1.15.
        assert_eq!(price_wei, bidder::ONE_SALT_WEI * 115 / 100);
        // Latency arg mirrors the exec estimate, in milliseconds.
        assert_eq!(latency_ms, 600 * 1000);
    }

    // PBA-L6b-025: a job that is no longer open for bids (assigned, expired,
    // or past its bid deadline) must never be bid on, whatever the bidder's
    // economics say.
    #[tokio::test]
    async fn l6b_025_closed_job_is_never_bid_on() {
        let state = shared();
        let mut snap = biddable_snapshot();
        snap.bid_expires_block = None;
        let view = FakeView {
            snapshot: snap,
            fail: false,
        };
        let placer = RecordingPlacer {
            placed: Mutex::new(Vec::new()),
            expires: Mutex::new(Vec::new()),
        };
        let out = tick(&state, &view, &on_settings(), &placer).await;
        assert_eq!(out, TickOutcome::NoBid);
        assert!(placer.placed.lock().expect("mutex").is_empty(), "no bid on a closed job");
    }

    // PBA-L6b-021 (R2 verifier): an open, profitable job whose on-chain
    // inputHash is not a bindable 32-byte keccak (CID bytes via the SDK's
    // documented path) reaches the tick through the same bridge gate the live
    // view uses, and must produce NO bid — so the provider never wins a job its
    // executor will refuse, and `timeoutJob` never slashes it.
    #[tokio::test]
    async fn l6b_021_unbindable_input_hash_places_no_bid() {
        use chainio::marketplace::{Job as ChainJob, JobState, VerificationTier as ChainTier};
        let mk = |input_hash| ChainJob {
            id: 7,
            requester: [0xaa; 20],
            model_hash: [0u8; 32],
            max_price_wei: 4 * bidder::ONE_SALT_WEI,
            tier: ChainTier::Commitment,
            state: JobState::Bidding,
            assigned_provider: [0; 20],
            escrow_wei: 4 * bidder::ONE_SALT_WEI,
            bid_deadline_block: 100,
            execution_deadline_block: 1000,
            created_at_block: 50,
            bid_count: 0,
            input_hash,
        };
        for (hash, want) in [
            (Some([0x11; 32]), TickOutcome::Bid),
            (None, TickOutcome::NoBid),
        ] {
            let state = shared();
            let mut snap = biddable_snapshot();
            snap.bid_expires_block = crate::bridge::bid_expires_block(&mk(hash), 50);
            let view = FakeView {
                snapshot: snap,
                fail: false,
            };
            let placer = RecordingPlacer {
                placed: Mutex::new(Vec::new()),
                expires: Mutex::new(Vec::new()),
            };
            assert_eq!(tick(&state, &view, &on_settings(), &placer).await, want);
            assert_eq!(
                placer.placed.lock().expect("mutex").is_empty(),
                want == TickOutcome::NoBid,
                "PBA-L6b-021: bid iff the inputHash is bindable (hash={hash:?})"
            );
        }
    }

    // PBA-L6b-025: the queued bid expires at the job's bid deadline, not 0.
    #[tokio::test]
    async fn l6b_025_bid_carries_the_bid_deadline_as_expiry() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(), // bid_expires_block = Some(100)
            fail: false,
        };
        let placer = RecordingPlacer {
            placed: Mutex::new(Vec::new()),
            expires: Mutex::new(Vec::new()),
        };
        assert_eq!(tick(&state, &view, &on_settings(), &placer).await, TickOutcome::Bid);
        assert_eq!(*placer.expires.lock().expect("mutex"), vec![100]);
    }

    /// A Skip decision must never reach the placer.
    #[tokio::test]
    async fn skip_decision_places_no_bid() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let placer = RecordingPlacer {
            placed: Mutex::new(Vec::new()),
            expires: Mutex::new(Vec::new()),
        };
        let mut s = on_settings();
        s.enabled = false;
        tick(&state, &view, &s, &placer).await;
        assert!(placer.placed.lock().expect("mutex not poisoned").is_empty());
    }

    /// SELL-S1 gate: "slash alert fires in <2 min". The detector runs inside
    /// every tick, and the production tick interval is the 30s heartbeat
    /// cadence — so a slash lands in `/health.alert` within ONE tick, 30s,
    /// well inside the 2-minute budget.
    #[tokio::test]
    async fn slash_alert_fires_within_one_tick_of_the_stake_drop() {
        let state = shared();
        let healthy = biddable_snapshot();
        let mut slashed = biddable_snapshot();
        slashed.stake_wei = healthy.stake_wei - healthy.stake_wei / 20; // -5% slash
        let view = SequenceView {
            snapshots: Mutex::new(vec![healthy]),
            last: slashed,
        };
        tick(&state, &view, &on_settings(), &NoBids).await;
        assert_eq!(
            state.read().await.health_at(0).alert,
            None,
            "no alert before the slash"
        );
        tick(&state, &view, &on_settings(), &NoBids).await;
        let alert = state
            .read()
            .await
            .health_at(0)
            .alert
            .expect("slash alert raised on the very tick the stake dropped");
        assert!(alert.contains("slash"), "alert was: {alert}");
    }

    /// Reputation drop >5% between ticks surfaces in /health.alert (the GUI
    /// polls /health and alerts the operator — SELL-S1 BDD line).
    #[tokio::test]
    async fn reputation_drop_alert_fires_and_latches() {
        let state = shared();
        let healthy = biddable_snapshot();
        let mut dropped = biddable_snapshot();
        dropped.reputation_bps = 8700; // 9230 → 8700 is -5.74%
        let view = SequenceView {
            snapshots: Mutex::new(vec![healthy]),
            last: dropped,
        };
        tick(&state, &view, &on_settings(), &NoBids).await;
        tick(&state, &view, &on_settings(), &NoBids).await;
        let alert = state.read().await.health_at(0).alert.clone()
            .expect("reputation alert raised");
        assert!(alert.contains("reputation"), "alert was: {alert}");
        // A third (now-stable) tick must not clear it — it latches until the
        // operator acknowledges.
        tick(&state, &view, &on_settings(), &NoBids).await;
        assert!(
            state.read().await.health_at(0).alert.is_some(),
            "alert latches across healthy ticks"
        );
    }

    #[tokio::test]
    async fn refresh_error_records_last_error_and_goes_idle() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: true,
        };
        let out = tick(&state, &view, &on_settings(), &NoBids).await;
        assert_eq!(out, TickOutcome::RefreshError);
        let h = state.read().await.health_at(0);
        assert_eq!(h.state.as_str(), "idle");
        assert!(h.last_error.unwrap().contains("market refresh failed"));
    }

    #[tokio::test]
    async fn beat_records_heartbeat_age() {
        let state = shared();
        let sender = CountingSender {
            beats: Mutex::new(0),
        };
        // Before any beat, age is None.
        assert_eq!(state.read().await.health().heartbeat_age_secs, None);
        beat(&state, &sender).await.unwrap();
        assert_eq!(*sender.beats.lock().unwrap(), 1);
        // After a beat, age is Some (just now → small).
        assert!(state.read().await.health().heartbeat_age_secs.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn run_loop_beats_once_per_tick_on_cadence() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let sender = CountingSender {
            beats: Mutex::new(0),
        };
        run_loop(
            state.clone(),
            &view,
            &sender,
            &crate::execution::NoExecutor,
            &NoBids,
            &on_settings(),
            heartbeat::HEARTBEAT_INTERVAL,
            Some(3),
        )
        .await;
        // One heartbeat per tick.
        assert_eq!(*sender.beats.lock().unwrap(), 3);
        // Last tick was a bid.
        assert_eq!(state.read().await.health_at(0).state.as_str(), "bidding");
    }

    // ── PBA-L6b-008: schedule + compute.json are re-evaluated every tick ──

    /// Counts placed bids.
    struct CountingBids(Mutex<u64>);
    impl BidPlacer for CountingBids {
        async fn place(&self, _: u128, _: u128, _: u128, _: u128) -> Result<(), String> {
            *self.0.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// A TickExecutor that runs `f` after every tick (advances the virtual
    /// clock / rewrites compute.json between ticks).
    struct Between<F: Fn() + Sync>(F);
    impl<F: Fn() + Sync> crate::execution::TickExecutor for Between<F> {
        async fn tick(&self, _state: &SharedState) {
            (self.0)();
        }
    }

    fn l6b008_config(tag: &str, json: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("citrate-l6b008-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("compute.json");
        std::fs::write(&p, json).unwrap();
        p
    }

    // Virtual time crossing a window boundary: a Nights node started at 23:00
    // (inside its window) must stop bidding once the clock reaches 11:00.
    #[tokio::test(start_paused = true)]
    async fn l6b_008_schedule_is_evaluated_against_the_clock_each_tick() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let path = l6b008_config("clock", r#"{ "enabled": true, "schedule": "nights" }"#);
        // Epoch day 0 (Thursday) 23:00 UTC.
        let clock = Arc::new(AtomicU64::new(23 * 3600));
        let c = clock.clone();
        let live = LiveSettings {
            config_path: path.clone(),
            now: move || c.load(Ordering::SeqCst),
        };
        let bids = CountingBids(Mutex::new(0));
        let adv = clock.clone();
        let exec = Between(move || {
            adv.fetch_add(12 * 3600, Ordering::SeqCst); // → Friday 11:00
        });
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let sender = CountingSender {
            beats: Mutex::new(0),
        };
        run_loop(
            shared(),
            &view,
            &sender,
            &exec,
            &bids,
            &live,
            heartbeat::HEARTBEAT_INTERVAL,
            Some(2),
        )
        .await;
        assert_eq!(
            *bids.0.lock().unwrap(),
            1,
            "bid at 23:00 only; 11:00 is outside the Nights window"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // compute.json is re-read every tick: flipping `enabled` off stops bidding
    // without a restart, and an unreadable file fails closed (no bid, error
    // recorded).
    #[tokio::test(start_paused = true)]
    async fn l6b_008_compute_json_is_reloaded_each_tick_and_fails_closed() {
        let path = l6b008_config("reload", r#"{ "enabled": true, "schedule": "always" }"#);
        let live = LiveSettings {
            config_path: path.clone(),
            now: || 12 * 3600,
        };
        let bids = CountingBids(Mutex::new(0));
        let step = std::sync::atomic::AtomicU64::new(0);
        let p2 = path.clone();
        let exec = Between(move || {
            match step.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => std::fs::write(&p2, r#"{ "enabled": false, "schedule": "always" }"#).unwrap(),
                1 => std::fs::write(&p2, "not json").unwrap(),
                _ => {}
            }
        });
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let sender = CountingSender {
            beats: Mutex::new(0),
        };
        let state = shared();
        run_loop(
            state.clone(),
            &view,
            &sender,
            &exec,
            &bids,
            &live,
            heartbeat::HEARTBEAT_INTERVAL,
            Some(3),
        )
        .await;
        assert_eq!(*bids.0.lock().unwrap(), 1, "only the first (enabled) tick bids");
        let err = state.read().await.health_at(0).last_error;
        assert!(
            err.as_deref().is_some_and(|e| e.contains("settings reload failed")),
            "a bad compute.json must be surfaced, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
