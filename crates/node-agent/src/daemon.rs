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
    /// The job under consideration this tick.
    pub job: BidJob,
    /// The pricing oracle reading.
    pub oracle: ComputePricingOracle,
}

/// Source of [`MarketSnapshot`]s. Async so the live implementation can do RPC.
pub trait MarketView {
    /// Refresh the market view for this tick.
    fn refresh(
        &self,
    ) -> impl std::future::Future<Output = Result<MarketSnapshot, String>> + Send;
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
pub async fn tick<V: MarketView>(state: &SharedState, view: &V, settings: &Settings) -> TickOutcome {
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
        w.set_provider_stats(
            snapshot.caps.max_concurrent_jobs as u32,
            snapshot.reputation_bps,
        );
        // A successful refresh clears any prior transient error.
        w.set_last_error(None);
    }

    // 3. Respect pause: do not evaluate NEW bids while paused.
    if !state.read().await.accepts_new_bids() {
        return TickOutcome::SkippedPaused;
    }

    // Run the pure bidder and record the resulting tick state.
    let decision = bidder::evaluate(&snapshot.job, &snapshot.oracle, settings, &snapshot.caps);
    let mut w = state.write().await;
    match decision {
        BidDecision::Bid { .. } => {
            w.set_bidding(true);
            TickOutcome::Bid
        }
        BidDecision::Skip { .. } => {
            w.set_idle();
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
) -> Result<(), HeartbeatError> {
    let calldata = heartbeat::heartbeat_calldata();
    let res = sender.send_heartbeat(&calldata).await;
    let mut w = state.write().await;
    match &res {
        Ok(()) => {
            w.record_heartbeat();
        }
        Err(e) => {
            w.set_last_error(Some(e.to_string()));
        }
    }
    res
}

/// Run the supervised loop until `max_ticks` ticks have run (`None` = forever).
///
/// Each tick runs [`tick`] then [`beat`] (the heartbeat cadence is one beat per
/// tick here; in production the tick interval *is* the heartbeat interval). The
/// loop never returns on a heartbeat error — it records it and keeps going.
pub async fn run_loop<V, S>(
    state: SharedState,
    view: &V,
    sender: &S,
    settings: &Settings,
    interval: Duration,
    max_ticks: Option<u64>,
) where
    V: MarketView,
    S: HeartbeatSender,
{
    let mut ticks: u64 = 0;
    loop {
        if let Some(max) = max_ticks {
            if ticks >= max {
                return;
            }
        }
        tick(&state, view, settings).await;
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
        async fn send_heartbeat(&self, _calldata: &[u8]) -> Result<(), HeartbeatError> {
            *self.beats.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn tick_records_bidding_and_provider_stats() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: false,
        };
        let out = tick(&state, &view, &on_settings()).await;
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
        let out = tick(&state, &view, &s).await;
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
        let out = tick(&state, &view, &on_settings()).await;
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
        tick(&state, &view, &on_settings()).await;
        // In-flight count survives the paused tick (jobs finish, not cancelled).
        assert_eq!(state.read().await.health_at(0).active_jobs, 2);
    }

    #[tokio::test]
    async fn refresh_error_records_last_error_and_goes_idle() {
        let state = shared();
        let view = FakeView {
            snapshot: biddable_snapshot(),
            fail: true,
        };
        let out = tick(&state, &view, &on_settings()).await;
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
}
