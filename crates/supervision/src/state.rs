//! `state` — the supervised agent's observable state machine.
//!
//! [`AgentState`] is the single shared record the daemon loop writes and the
//! supervision HTTP endpoints read. It is deliberately free of chain/ABI/key
//! concerns: the loop feeds it primitives (heartbeat timestamps, active-job
//! counts, reputation, the last bid decision) and the endpoints serialize a
//! [`Health`] snapshot from it.
//!
//! The state machine is small and total:
//!   - `Idle`      — running, no job in flight, not currently mid-evaluation.
//!   - `Bidding`   — evaluating / has just decided to bid on a job.
//!   - `Executing` — at least one job is in flight (S2 work; the count is
//!     surfaced now so the GUI and pause semantics are real today).
//!   - `Paused`    — the operator paused new bidding via `/pause`.
//!
//! Pause semantics (SELL-S1 acceptance): `/pause` sets `Paused` and makes
//! [`AgentState::accepts_new_bids`] return `false`, so the daemon loop skips
//! evaluating *new* jobs — but in-flight jobs keep their `active_jobs` count and
//! are allowed to finish (nothing here cancels them). `/resume` clears the pause
//! and the loop's next tick recomputes a running state from the live counts.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// The coarse lifecycle state the GUI observes via `/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleState {
    /// Running, idle — no in-flight job, not mid-evaluation.
    Idle,
    /// Actively evaluating / decided to bid this tick.
    Bidding,
    /// One or more jobs are in flight.
    Executing,
    /// Operator paused new bidding (in-flight jobs still finish).
    Paused,
}

impl LifecycleState {
    /// The exact `/status` string for this state.
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Idle => "idle",
            LifecycleState::Bidding => "bidding",
            LifecycleState::Executing => "executing",
            LifecycleState::Paused => "paused",
        }
    }
}

/// The JSON body served by `GET /health`.
///
/// `heartbeat_age_secs` is `None` until the first heartbeat is recorded (so the
/// GUI can tell "never beat" from "beat 0s ago"); everything else is always
/// present so the GUI's health gauge is total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    /// Coarse lifecycle state (mirrors `/status`).
    pub state: LifecycleState,
    /// Seconds since the last heartbeat was sent, or `None` if none yet.
    pub heartbeat_age_secs: Option<u64>,
    /// Number of jobs currently in flight.
    pub active_jobs: u32,
    /// Configured concurrency ceiling (`maxConcurrentJobs`).
    pub max_concurrent: u32,
    /// Provider reputation in basis points (0..=10000), from the last chain read.
    pub reputation_bps: u32,
    /// Last error the loop recorded (heartbeat send failure, RPC blip, …), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Operator alert (slash detected / reputation drop >5% since last poll).
    /// Latched until [`AgentState::clear_alert`] — a GUI that polls `/health`
    /// can never miss it between polls (SELL-S1 acceptance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
}

/// One unsigned chain write the daemon needs a signing surface (gui-native /
/// relay) to sign + broadcast. Served by `GET /signature-requests`; the surface
/// reports back via `POST /signature-requests/{id}/observed`.
///
/// Numeric `value_wei`/`expires_block` are decimal **strings** so a JS/JSON
/// consumer never loses precision on a `u128`. Held free of chain/key types —
/// the daemon converts raw bytes/addresses to hex before enqueueing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingSignatureRequest {
    /// Stable id for the observe callback.
    pub id: u64,
    /// The write's function name (`startExecution`, `submitCommitment`, …).
    pub intent: String,
    /// Target contract, `0x`-hex.
    pub to: String,
    /// ABI calldata, `0x`-hex.
    pub calldata: String,
    /// Wei to send, decimal string (0 for the SELL-S2 writes).
    pub value_wei: String,
    /// Chain id the tx must be signed for.
    pub chain_id: u64,
    /// Human-readable description for the signing UI.
    pub context: String,
    /// Advisory block height past which signing is pointless (decimal string).
    pub expires_block: String,
    /// `"pending"` (awaiting signing) or `"submitted"` (broadcast + observed).
    pub status: String,
    /// The broadcast tx hash once observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// Monotonic-ish wall clock used for heartbeat-age math. Pulled out behind a
/// function so tests can drive it deterministically.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The shared, mutable agent state. Wrapped in `Arc<RwLock<…>>` by the daemon so
/// the loop and the HTTP handlers share one record.
///
/// `Default` yields a fresh, running, un-paused agent (all counters zero, no
/// heartbeat yet) — see the field defaults below.
#[derive(Debug, Clone, Default)]
pub struct AgentState {
    /// Operator pause flag. When set, no new bids are evaluated.
    paused: bool,
    /// Whether the current tick is mid-evaluation / decided to bid.
    bidding: bool,
    /// Jobs currently in flight (S2 fills this; S1 keeps it at 0 unless a test
    /// or future executor increments it).
    active_jobs: u32,
    /// Concurrency ceiling from the provider profile.
    max_concurrent: u32,
    /// Reputation in basis points from the last chain read.
    reputation_bps: u32,
    /// UNIX seconds of the last heartbeat, or `None` if none sent yet.
    last_heartbeat_unix: Option<u64>,
    /// Last recorded error string, if any.
    last_error: Option<String>,
    /// Unsigned chain writes queued for the signing surface (the relay).
    pending_requests: Vec<PendingSignatureRequest>,
    /// Monotonic id source for `pending_requests`.
    next_request_id: u64,
    /// Latched operator alert (slash / reputation drop). See [`Health::alert`].
    alert: Option<String>,
    /// Reputation at the previous observation, for the >5%-drop detector.
    prev_reputation_bps: Option<u32>,
    /// Stake at the previous observation, for the slash detector.
    prev_stake_wei: Option<u128>,
}

impl AgentState {
    /// A fresh, running, un-paused state.
    pub fn new() -> Self {
        Self::default()
    }

    // ---- pause / resume (the supervision control surface) ----

    /// Pause new bidding. In-flight jobs keep running; only *new* bids stop.
    /// Idempotent.
    pub fn pause(&mut self) {
        self.paused = true;
        // Stop advertising "bidding" the instant we pause.
        self.bidding = false;
    }

    /// Resume bidding after a pause. Idempotent.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Is the agent currently paused?
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether the daemon loop should evaluate *new* jobs this tick. False while
    /// paused — the core of the pause semantics.
    pub fn accepts_new_bids(&self) -> bool {
        !self.paused
    }

    // ---- loop-fed inputs ----

    /// Mark that the loop is evaluating / has decided to bid this tick. A no-op
    /// while paused (paused never reports `bidding`).
    pub fn set_bidding(&mut self, bidding: bool) {
        if self.paused {
            self.bidding = false;
        } else {
            self.bidding = bidding;
        }
    }

    /// Record that the loop is idle this tick (cleared the bidding flag).
    pub fn set_idle(&mut self) {
        self.bidding = false;
    }

    /// Set the in-flight job count (executor-driven; S2). Provided now so the
    /// `executing` state and `/health.active_jobs` are real.
    pub fn set_active_jobs(&mut self, active: u32) {
        self.active_jobs = active;
    }

    /// Update capacity + reputation from a fresh provider read.
    pub fn set_provider_stats(&mut self, max_concurrent: u32, reputation_bps: u32) {
        self.max_concurrent = max_concurrent;
        self.reputation_bps = reputation_bps;
    }

    /// Record a full provider observation (capacity, reputation, stake) and
    /// raise operator alerts on dangerous deltas versus the PREVIOUS
    /// observation (SELL-S1 acceptance):
    ///
    /// - **reputation drop strictly >5%** relative to the last poll
    ///   (`ComputeLib` weighs reputation at 30% — a sliding score quietly
    ///   loses every bid), and
    /// - **any stake decrease** — `ComputeMarketplace` slashes 5% of stake on
    ///   timeout/failure, so a falling stake means the provider was slashed.
    ///
    /// Alerts latch in `/health.alert` until [`Self::clear_alert`] so a GUI
    /// polling between daemon ticks can never miss one. With the production
    /// 30s tick cadence, detection is well inside the 2-minute gate.
    pub fn record_provider_observation(
        &mut self,
        max_concurrent: u32,
        reputation_bps: u32,
        stake_wei: u128,
    ) {
        let mut alerts: Vec<String> = Vec::new();
        if let Some(prev) = self.prev_reputation_bps {
            // Strictly >5% relative drop: new < prev * 0.95, in integer math.
            if u64::from(reputation_bps) * 100 < u64::from(prev) * 95 {
                alerts.push(format!(
                    "reputation dropped >5% since last poll: {prev} → {reputation_bps} bps"
                ));
            }
        }
        if let Some(prev) = self.prev_stake_wei {
            if stake_wei < prev {
                alerts.push(format!(
                    "stake slashed: {prev} → {stake_wei} wei"
                ));
            }
        }
        if !alerts.is_empty() {
            self.alert = Some(alerts.join("; "));
        }
        self.prev_reputation_bps = Some(reputation_bps);
        self.prev_stake_wei = Some(stake_wei);
        self.set_provider_stats(max_concurrent, reputation_bps);
    }

    /// The latched operator alert, if any.
    pub fn alert(&self) -> Option<&str> {
        self.alert.as_deref()
    }

    /// Clear the latched alert (operator acknowledged it).
    pub fn clear_alert(&mut self) {
        self.alert = None;
    }

    /// Record a heartbeat sent now (uses the wall clock).
    pub fn record_heartbeat(&mut self) {
        self.last_heartbeat_unix = Some(now_unix_secs());
    }

    /// Record a heartbeat sent at an explicit UNIX time (for deterministic tests).
    pub fn record_heartbeat_at(&mut self, unix_secs: u64) {
        self.last_heartbeat_unix = Some(unix_secs);
    }

    /// Record (or clear, with `None`) the last error string.
    pub fn set_last_error(&mut self, err: Option<String>) {
        self.last_error = err;
    }

    // ---- signing relay queue (the daemon enqueues; the GUI/relay drains) ----

    /// Enqueue an unsigned chain write for the signing surface. **Idempotent by
    /// `calldata`**: re-emitting the same write (which the daemon does every tick
    /// until the chain advances) returns the existing id instead of duplicating —
    /// so the relay never double-broadcasts. Returns the request id.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_signature_request(
        &mut self,
        intent: String,
        to: String,
        calldata: String,
        value_wei: u128,
        chain_id: u64,
        context: String,
        expires_block: u128,
    ) -> u64 {
        if let Some(existing) = self.pending_requests.iter().find(|r| r.calldata == calldata) {
            return existing.id;
        }
        let id = self.next_request_id;
        self.next_request_id += 1;
        self.pending_requests.push(PendingSignatureRequest {
            id,
            intent,
            to,
            calldata,
            value_wei: value_wei.to_string(),
            chain_id,
            context,
            expires_block: expires_block.to_string(),
            status: "pending".to_string(),
            tx_hash: None,
        });
        id
    }

    /// All queued requests (pending + submitted), for `GET /signature-requests`.
    pub fn signature_requests(&self) -> Vec<PendingSignatureRequest> {
        self.pending_requests.clone()
    }

    /// Mark a request observed (signed + broadcast) with its `tx_hash`. Returns
    /// `false` if no such id. Submitted entries stay (so a chain-lag re-emit
    /// still dedups and can't double-broadcast).
    pub fn mark_request_observed(&mut self, id: u64, tx_hash: String) -> bool {
        if let Some(r) = self.pending_requests.iter_mut().find(|r| r.id == id) {
            r.status = "submitted".to_string();
            r.tx_hash = Some(tx_hash);
            true
        } else {
            false
        }
    }

    // ---- derived views (read by the HTTP handlers) ----

    /// The coarse lifecycle state. Precedence: paused > executing > bidding > idle.
    pub fn lifecycle(&self) -> LifecycleState {
        if self.paused {
            LifecycleState::Paused
        } else if self.active_jobs > 0 {
            LifecycleState::Executing
        } else if self.bidding {
            LifecycleState::Bidding
        } else {
            LifecycleState::Idle
        }
    }

    /// Heartbeat age in seconds relative to `now_unix`, saturating at 0 if the
    /// recorded beat is somehow in the future (clock skew).
    pub fn heartbeat_age_secs_at(&self, now_unix: u64) -> Option<u64> {
        self.last_heartbeat_unix
            .map(|t| now_unix.saturating_sub(t))
    }

    /// Build the `/health` snapshot using the current wall clock.
    pub fn health(&self) -> Health {
        self.health_at(now_unix_secs())
    }

    /// Build the `/health` snapshot relative to an explicit `now_unix` (tests).
    pub fn health_at(&self, now_unix: u64) -> Health {
        Health {
            state: self.lifecycle(),
            heartbeat_age_secs: self.heartbeat_age_secs_at(now_unix),
            active_jobs: self.active_jobs,
            max_concurrent: self.max_concurrent,
            reputation_bps: self.reputation_bps,
            last_error: self.last_error.clone(),
            alert: self.alert.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_idle_and_accepts_bids() {
        let s = AgentState::new();
        assert_eq!(s.lifecycle(), LifecycleState::Idle);
        assert_eq!(s.lifecycle().as_str(), "idle");
        assert!(s.accepts_new_bids());
        assert!(!s.is_paused());
    }

    #[test]
    fn bidding_flag_moves_idle_to_bidding() {
        let mut s = AgentState::new();
        s.set_bidding(true);
        assert_eq!(s.lifecycle(), LifecycleState::Bidding);
        s.set_idle();
        assert_eq!(s.lifecycle(), LifecycleState::Idle);
    }

    #[test]
    fn active_jobs_make_it_executing_over_bidding() {
        let mut s = AgentState::new();
        s.set_bidding(true);
        s.set_active_jobs(1);
        // Executing takes precedence over bidding.
        assert_eq!(s.lifecycle(), LifecycleState::Executing);
        assert_eq!(s.lifecycle().as_str(), "executing");
    }

    #[test]
    fn pause_blocks_new_bids_but_not_inflight() {
        let mut s = AgentState::new();
        s.set_active_jobs(2); // two jobs in flight
        s.pause();
        assert!(s.is_paused());
        assert!(!s.accepts_new_bids());
        // Paused state is reported even with jobs in flight...
        assert_eq!(s.lifecycle(), LifecycleState::Paused);
        // ...but the in-flight count is untouched (jobs keep running).
        assert_eq!(s.health_at(0).active_jobs, 2);
    }

    #[test]
    fn paused_never_reports_bidding() {
        let mut s = AgentState::new();
        s.pause();
        // The loop tries to mark bidding while paused — it must be ignored.
        s.set_bidding(true);
        assert_eq!(s.lifecycle(), LifecycleState::Paused);
    }

    #[test]
    fn resume_restores_bid_acceptance() {
        let mut s = AgentState::new();
        s.pause();
        assert!(!s.accepts_new_bids());
        s.resume();
        assert!(s.accepts_new_bids());
        assert_eq!(s.lifecycle(), LifecycleState::Idle);
    }

    #[test]
    fn pause_and_resume_are_idempotent() {
        let mut s = AgentState::new();
        s.pause();
        s.pause();
        assert!(s.is_paused());
        s.resume();
        s.resume();
        assert!(!s.is_paused());
    }

    #[test]
    fn heartbeat_age_is_none_until_first_beat_then_counts_up() {
        let mut s = AgentState::new();
        assert_eq!(s.health_at(1000).heartbeat_age_secs, None);
        s.record_heartbeat_at(1000);
        assert_eq!(s.heartbeat_age_secs_at(1000), Some(0));
        assert_eq!(s.heartbeat_age_secs_at(1030), Some(30));
    }

    #[test]
    fn heartbeat_age_saturates_on_future_clock_skew() {
        let mut s = AgentState::new();
        s.record_heartbeat_at(2000);
        // "now" earlier than the recorded beat → saturate to 0, not underflow.
        assert_eq!(s.heartbeat_age_secs_at(1900), Some(0));
    }

    #[test]
    fn health_snapshot_carries_provider_stats_and_error() {
        let mut s = AgentState::new();
        s.set_provider_stats(10, 9230);
        s.set_active_jobs(3);
        s.set_last_error(Some("rpc blip".into()));
        s.record_heartbeat_at(500);
        let h = s.health_at(530);
        assert_eq!(h.max_concurrent, 10);
        assert_eq!(h.reputation_bps, 9230);
        assert_eq!(h.active_jobs, 3);
        assert_eq!(h.heartbeat_age_secs, Some(30));
        assert_eq!(h.last_error.as_deref(), Some("rpc blip"));
        assert_eq!(h.state, LifecycleState::Executing);
    }

    #[test]
    fn health_omits_last_error_when_none() {
        let s = AgentState::new();
        let json = serde_json::to_string(&s.health_at(0)).unwrap();
        assert!(!json.contains("last_error"), "json was: {json}");
        // status string is present and lowercase.
        assert!(json.contains("\"state\":\"idle\""), "json was: {json}");
    }

    #[test]
    fn health_includes_last_error_when_set() {
        let mut s = AgentState::new();
        s.set_last_error(Some("boom".into()));
        let json = serde_json::to_string(&s.health_at(0)).unwrap();
        assert!(json.contains("\"last_error\":\"boom\""), "json was: {json}");
    }

    // ---- SELL-S1 operator alerts (reputation drop >5%, slash) ----

    #[test]
    fn reputation_drop_over_5pct_raises_alert() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 9230, 1_000_000);
        assert_eq!(s.health_at(0).alert, None, "first observation never alerts");
        // 9230 → 8700 bps is a 5.74% relative drop — must alert.
        s.record_provider_observation(10, 8700, 1_000_000);
        let alert = s.health_at(0).alert.expect("reputation-drop alert raised");
        assert!(alert.contains("9230"), "alert was: {alert}");
        assert!(alert.contains("8700"), "alert was: {alert}");
        assert!(alert.contains("reputation"), "alert was: {alert}");
    }

    #[test]
    fn reputation_drop_of_exactly_5pct_is_quiet() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 10_000, 1_000_000);
        // 10000 → 9500 is exactly 5%, the spec says strictly >5%.
        s.record_provider_observation(10, 9_500, 1_000_000);
        assert_eq!(s.health_at(0).alert, None);
    }

    #[test]
    fn reputation_rise_is_quiet() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 9000, 1_000_000);
        s.record_provider_observation(10, 9600, 1_000_000);
        assert_eq!(s.health_at(0).alert, None);
    }

    #[test]
    fn stake_decrease_raises_slash_alert() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 9230, 1_000_000_000);
        // ComputeMarketplace slashes 5% of stake on timeout/failure.
        s.record_provider_observation(10, 9230, 950_000_000);
        let alert = s.health_at(0).alert.expect("slash alert raised");
        assert!(alert.contains("slash"), "alert was: {alert}");
        assert!(alert.contains("1000000000"), "alert was: {alert}");
        assert!(alert.contains("950000000"), "alert was: {alert}");
    }

    #[test]
    fn simultaneous_slash_and_reputation_drop_reports_both() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 9230, 1_000_000_000);
        s.record_provider_observation(10, 8000, 950_000_000);
        let alert = s.health_at(0).alert.expect("alert raised");
        assert!(alert.contains("reputation"), "alert was: {alert}");
        assert!(alert.contains("slash"), "alert was: {alert}");
    }

    #[test]
    fn alert_latches_across_healthy_observations() {
        let mut s = AgentState::new();
        s.record_provider_observation(10, 9230, 1_000_000_000);
        s.record_provider_observation(10, 9230, 950_000_000); // slash
        assert!(s.health_at(0).alert.is_some());
        // A later healthy read must NOT silently clear the alert — the
        // operator may not have polled yet.
        s.record_provider_observation(10, 9230, 950_000_000);
        assert!(
            s.health_at(0).alert.is_some(),
            "alert must latch until explicitly cleared"
        );
        s.clear_alert();
        assert_eq!(s.health_at(0).alert, None);
    }

    #[test]
    fn record_provider_observation_updates_provider_stats() {
        let mut s = AgentState::new();
        s.record_provider_observation(7, 8800, 42);
        let h = s.health_at(0);
        assert_eq!(h.max_concurrent, 7);
        assert_eq!(h.reputation_bps, 8800);
    }

    #[test]
    fn health_omits_alert_when_none_and_includes_when_set() {
        let mut s = AgentState::new();
        let json = serde_json::to_string(&s.health_at(0)).expect("serializes");
        assert!(!json.contains("alert"), "json was: {json}");
        s.record_provider_observation(10, 9230, 100);
        s.record_provider_observation(10, 9230, 50);
        let json = serde_json::to_string(&s.health_at(0)).expect("serializes");
        assert!(json.contains("\"alert\":"), "json was: {json}");
    }

    #[test]
    fn enqueue_assigns_ids_and_lists_requests() {
        let mut s = AgentState::new();
        let id0 = s.enqueue_signature_request(
            "startExecution".into(),
            "0x11".into(),
            "0xaaaa".into(),
            0,
            40204,
            "startExecution job 7".into(),
            200,
        );
        let id1 = s.enqueue_signature_request(
            "submitCommitment".into(),
            "0x11".into(),
            "0xbbbb".into(),
            0,
            40204,
            "submitCommitment job 7".into(),
            200,
        );
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        let reqs = s.signature_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].intent, "startExecution");
        assert_eq!(reqs[0].status, "pending");
        assert_eq!(reqs[0].value_wei, "0");
    }

    #[test]
    fn enqueue_is_idempotent_by_calldata() {
        let mut s = AgentState::new();
        let a = s.enqueue_signature_request(
            "startExecution".into(),
            "0x11".into(),
            "0xaaaa".into(),
            0,
            40204,
            "ctx".into(),
            200,
        );
        // Same calldata re-emitted next tick → same id, no duplicate entry.
        let b = s.enqueue_signature_request(
            "startExecution".into(),
            "0x11".into(),
            "0xaaaa".into(),
            0,
            40204,
            "ctx".into(),
            200,
        );
        assert_eq!(a, b);
        assert_eq!(s.signature_requests().len(), 1);
    }

    #[test]
    fn mark_observed_sets_status_and_tx_hash() {
        let mut s = AgentState::new();
        let id = s.enqueue_signature_request(
            "completeJob".into(),
            "0x11".into(),
            "0xcccc".into(),
            0,
            40204,
            "ctx".into(),
            0,
        );
        assert!(s.mark_request_observed(id, "0xdeadbeef".into()));
        let r = &s.signature_requests()[0];
        assert_eq!(r.status, "submitted");
        assert_eq!(r.tx_hash.as_deref(), Some("0xdeadbeef"));
        // An observed entry still dedups a chain-lag re-emit (no double-broadcast).
        let again = s.enqueue_signature_request(
            "completeJob".into(),
            "0x11".into(),
            "0xcccc".into(),
            0,
            40204,
            "ctx".into(),
            0,
        );
        assert_eq!(again, id);
        assert_eq!(s.signature_requests().len(), 1);
    }

    #[test]
    fn mark_observed_unknown_id_is_false() {
        let mut s = AgentState::new();
        assert!(!s.mark_request_observed(99, "0x".into()));
    }
}
