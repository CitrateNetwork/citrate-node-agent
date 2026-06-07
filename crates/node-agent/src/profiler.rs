//! `profiler` — per-model work estimates from the executor's real runs.
//!
//! SELL-S1 fed the bidder a single hardcoded work estimate (0.5 pflop-hours /
//! 300s) for every job (TD-10). Now that the executor runs real inference, the
//! agent **measures** each model's wall-clock execution time and feeds an EWMA
//! back into the next bid — so the cost-plus price and the deadline-feasibility
//! gate track reality instead of a guess.
//!
//! - `exec_secs` is measured directly (the load-bearing input to the deadline gate).
//! - `pflop_hours` (the compute-work figure for pricing) is derived from the
//!   measured time × the node's configured throughput: `work = hours × pflops`.
//!   We can't count FLOPs without instrumentation, but grounding the estimate in
//!   measured time + known hardware throughput beats a flat constant.
//!
//! Until a model has a sample, `estimate` returns the configured defaults (chosen
//! so an unprofiled node reproduces the old SELL-S1 numbers exactly).

use std::collections::HashMap;
use std::sync::Mutex;

/// EWMA smoothing factor for new samples (0..1). 0.3 = react to change but don't
/// let one slow/fast run swing the estimate wildly.
const ALPHA: f64 = 0.3;

/// Per-model execution-time profiler. Shared (`Arc`) between the executor (which
/// records) and the market view (which reads for the bid estimate).
pub struct ModelProfiler {
    /// Node throughput in pflops ×1e18 (operator-configured; how much compute the
    /// node sustains). Used to derive pflop-hours from measured exec time.
    node_pflops_1e18: u128,
    /// Fallback execution seconds for an unprofiled model.
    default_exec_secs: u64,
    /// model_hash → EWMA of measured wall-clock execution seconds.
    profiles: Mutex<HashMap<[u8; 32], f64>>,
}

impl ModelProfiler {
    /// `node_pflops_1e18` = the node's sustained throughput (pflops ×1e18);
    /// `default_exec_secs` = the estimate before any sample exists.
    pub fn new(node_pflops_1e18: u128, default_exec_secs: u64) -> Self {
        Self {
            node_pflops_1e18,
            default_exec_secs,
            profiles: Mutex::new(HashMap::new()),
        }
    }

    /// Record a measured wall-clock execution time for `model_hash` (EWMA update).
    /// The first sample seeds the estimate exactly; later samples blend in.
    pub fn record(&self, model_hash: [u8; 32], measured_exec_secs: u64) {
        let mut g = self.profiles.lock().unwrap();
        let entry = g.entry(model_hash).or_insert(measured_exec_secs as f64);
        *entry = ALPHA * measured_exec_secs as f64 + (1.0 - ALPHA) * *entry;
    }

    /// Estimate `(pflop_hours_1e18, exec_secs)` for `model_hash` — the profiled
    /// EWMA if sampled, else the default. `pflop_hours = exec_secs/3600 × node_pflops`.
    pub fn estimate(&self, model_hash: &[u8; 32]) -> (u128, u64) {
        let exec_secs = self
            .profiles
            .lock()
            .unwrap()
            .get(model_hash)
            .map(|e| e.round() as u64)
            .unwrap_or(self.default_exec_secs)
            .max(1);
        let pflop_hours_1e18 = self
            .node_pflops_1e18
            .saturating_mul(exec_secs as u128)
            / 3600;
        (pflop_hours_1e18, exec_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default node throughput so an unprofiled model reproduces the old SELL-S1
    /// numbers: 6 pflops × (300s/3600) = 0.5 pflop-hours.
    const NODE_PFLOPS_1E18: u128 = 6_000_000_000_000_000_000;
    const DEFAULT_EXEC_SECS: u64 = 300;

    fn profiler() -> ModelProfiler {
        ModelProfiler::new(NODE_PFLOPS_1E18, DEFAULT_EXEC_SECS)
    }

    #[test]
    fn unprofiled_model_returns_the_legacy_defaults() {
        let (pflop_hours, exec_secs) = profiler().estimate(&[0x01; 32]);
        assert_eq!(exec_secs, 300);
        assert_eq!(pflop_hours, 500_000_000_000_000_000); // 0.5 ×1e18
    }

    #[test]
    fn first_sample_seeds_the_estimate_exactly() {
        let p = profiler();
        let h = [0x02; 32];
        p.record(h, 120);
        let (pflop_hours, exec_secs) = p.estimate(&h);
        assert_eq!(exec_secs, 120);
        // 6e18 × 120 / 3600 = 0.2 ×1e18.
        assert_eq!(pflop_hours, 200_000_000_000_000_000);
    }

    #[test]
    fn ewma_blends_toward_new_samples() {
        let p = profiler();
        let h = [0x03; 32];
        p.record(h, 100); // seed = 100
        p.record(h, 200); // 0.3*200 + 0.7*100 = 130
        let (_, exec_secs) = p.estimate(&h);
        assert_eq!(exec_secs, 130);
    }

    #[test]
    fn profiles_are_per_model_independent() {
        let p = profiler();
        p.record([0xaa; 32], 60);
        p.record([0xbb; 32], 600);
        assert_eq!(p.estimate(&[0xaa; 32]).1, 60);
        assert_eq!(p.estimate(&[0xbb; 32]).1, 600);
        // An unseen model still gets the default.
        assert_eq!(p.estimate(&[0xcc; 32]).1, 300);
    }

    #[test]
    fn exec_secs_never_zero() {
        let p = ModelProfiler::new(NODE_PFLOPS_1E18, 0);
        // Default 0 is clamped to 1 so pricing/deadline math never divides oddly.
        assert_eq!(p.estimate(&[0x04; 32]).1, 1);
    }
}
