//! `heartbeat` — `HeartbeatMonitor.heartbeat()` calldata and the 30-second
//! liveness loop.
//!
//! Why this exists (SELL planset R2, the dangerous part): the marketplace
//! **slashes 5% of stake on timeout** and `HeartbeatMonitor` **suspends**
//! providers that miss heartbeats. An unattended "set and forget" machine must
//! therefore prove liveness on a fixed cadence or it gets suspended and stops
//! winning work (and risks slashing). `heartbeat()` takes no arguments, so the
//! calldata is exactly the 4-byte selector.
//!
//! The actual broadcast is abstracted behind the [`HeartbeatSender`] trait so
//! the loop is unit-testable offline (no chain, no keys, no real clock): the
//! tests drive a counting fake and assert the cadence and that the calldata is
//! the pinned selector.

use std::time::Duration;

/// Heartbeat cadence: every 30 seconds (SELL-S1 scenario "heartbeats keep the
/// provider active"). Kept well under the on-chain `heartbeatInterval` so a
/// single missed tick never trips suspension.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Build the `HeartbeatMonitor.heartbeat()` calldata (selector only — no args).
pub fn heartbeat_calldata() -> Vec<u8> {
    chainio::selectors::heartbeat().to_vec()
}

/// What a successful `send_heartbeat` actually did — the daemon records a
/// heartbeat timestamp only for a real broadcast, not for a queued request
/// (a queued heartbeat is recorded when the signing surface reports it
/// observed, so `/health.heartbeat_age` never lies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The tx was signed + broadcast by this sender.
    Broadcast,
    /// The write was queued for an external signing surface (ADR-agent-signing);
    /// broadcast happens later and is reported via the observe callback.
    Queued,
}

/// Abstracts the act of broadcasting a signed `heartbeat()` transaction. The
/// node-agent binary implements this over the signing-relay queue (the daemon
/// holds no keys); tests implement a counting fake.
pub trait HeartbeatSender {
    /// Send one heartbeat transaction carrying `calldata`. Returns what
    /// happened on success ([`SendOutcome`]).
    fn send_heartbeat(
        &self,
        calldata: &[u8],
    ) -> impl std::future::Future<Output = Result<SendOutcome, HeartbeatError>> + Send;
}

/// Error broadcasting a heartbeat.
#[derive(Debug)]
pub enum HeartbeatError {
    /// The underlying transport/broadcast failed; the message carries detail.
    Send(String),
}

impl core::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeartbeatError::Send(m) => write!(f, "heartbeat send failed: {m}"),
        }
    }
}

impl std::error::Error for HeartbeatError {}

/// Run the heartbeat loop: send a heartbeat immediately, then once per
/// `interval`, until `max_beats` have been sent (use `None` to run forever).
///
/// `max_beats` exists so callers (and tests) can run a bounded loop; the
/// node-agent passes `None` for a perpetual loop. Send failures are surfaced
/// via `on_error` but do **not** stop the loop — a transient RPC blip must not
/// silently kill liveness (that would get the provider suspended).
pub async fn run_heartbeat_loop<S, F>(
    sender: &S,
    interval: Duration,
    max_beats: Option<u64>,
    mut on_error: F,
) where
    S: HeartbeatSender,
    F: FnMut(&HeartbeatError),
{
    let calldata = heartbeat_calldata();
    let mut sent: u64 = 0;
    loop {
        if let Some(max) = max_beats {
            if sent >= max {
                return;
            }
        }
        if let Err(e) = sender.send_heartbeat(&calldata).await {
            on_error(&e);
        }
        sent += 1;
        if let Some(max) = max_beats {
            if sent >= max {
                return;
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn calldata_is_the_pinned_heartbeat_selector() {
        let cd = heartbeat_calldata();
        // heartbeat() selector = 0x3defb962 (pinned in chainio::selectors).
        assert_eq!(cd, vec![0x3d, 0xef, 0xb9, 0x62]);
        assert_eq!(cd.len(), 4);
        assert_eq!(cd.as_slice(), &chainio::selectors::heartbeat());
    }

    #[test]
    fn interval_is_30_seconds() {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(30));
    }

    /// A fake sender (Send + Sync) that records each beat's calldata.
    struct Counting {
        beats: Mutex<Vec<Vec<u8>>>,
        fail_first: bool,
    }
    impl HeartbeatSender for Counting {
        async fn send_heartbeat(&self, calldata: &[u8]) -> Result<SendOutcome, HeartbeatError> {
            let mut beats = self.beats.lock().unwrap();
            let n = beats.len();
            beats.push(calldata.to_vec());
            drop(beats);
            if self.fail_first && n == 0 {
                return Err(HeartbeatError::Send("simulated blip".into()));
            }
            Ok(SendOutcome::Broadcast)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn loop_sends_one_beat_per_interval() {
        let sender = Counting {
            beats: Mutex::new(Vec::new()),
            fail_first: false,
        };
        let mut errors = 0;
        // Bounded run: 3 beats.
        run_heartbeat_loop(&sender, HEARTBEAT_INTERVAL, Some(3), |_| errors += 1).await;
        let beats = sender.beats.lock().unwrap();
        assert_eq!(beats.len(), 3);
        assert_eq!(errors, 0);
        // Every beat carries the heartbeat() selector.
        for cd in beats.iter() {
            assert_eq!(cd, &vec![0x3d, 0xef, 0xb9, 0x62]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn loop_continues_after_a_send_error() {
        let sender = Counting {
            beats: Mutex::new(Vec::new()),
            fail_first: true,
        };
        let mut errors = 0;
        run_heartbeat_loop(&sender, HEARTBEAT_INTERVAL, Some(3), |_| errors += 1).await;
        // The first send failed but the loop kept going and still made 3 beats.
        assert_eq!(sender.beats.lock().unwrap().len(), 3);
        assert_eq!(errors, 1);
    }
}
