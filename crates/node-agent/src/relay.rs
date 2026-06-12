//! `relay` — the node-agent side of the signing relay.
//!
//! The daemon holds no keys (ADR-agent-signing). Instead of broadcasting, the
//! [`RelaySigner`] enqueues each unsigned write into the shared supervision
//! state, where the signing surface (gui-native / the IDP-adjacent relay) drains
//! it over `GET /signature-requests`, signs + broadcasts, and reports back via
//! `POST /signature-requests/{id}/observed`. The daemon then reads the resulting
//! chain state next tick (e.g. `ComputeVerifier.commitmentSubmitted`), so it
//! advances purely on chain truth — never on optimistic local state.
//!
//! Enqueue is idempotent by calldata, so the daemon re-emitting the same write
//! each tick (until the chain advances) never causes a double-broadcast.

use chainio::abi::hex_encode;
use lifecycle::{JobSigner, JobSignerError, SignatureRequest, TxObserved};
use supervision::SharedState;

/// Queues unsigned requests into the shared supervision state for the signing
/// surface to drain. Cheap to clone (holds the shared `Arc`).
#[derive(Clone)]
pub struct RelaySigner {
    state: SharedState,
}

impl RelaySigner {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl JobSigner for RelaySigner {
    async fn request(&self, req: SignatureRequest) -> Result<TxObserved, JobSignerError> {
        self.state.write().await.enqueue_signature_request(
            req.intent.label().to_string(),
            hex_encode(&req.to),
            hex_encode(&req.calldata),
            req.value_wei,
            req.chain_id,
            req.context,
            req.expires_block,
        );
        // Queued for the signing surface — not broadcast here, so no tx hash yet.
        Ok(TxObserved { tx_hash: None })
    }
}

/// Heartbeat sender over the signing relay: each beat enqueues (or **re-arms**)
/// the recurring `HeartbeatMonitor.heartbeat()` write for the signing surface.
/// `heartbeat()` calldata is identical every beat, so this uses the recurring
/// enqueue (a `submitted` entry flips back to `pending` on the next beat) —
/// plain dedup would sign liveness exactly once and the provider would be
/// suspended. The supervision state records the heartbeat timestamp when the
/// surface reports the broadcast observed, so `/health.heartbeat_age` reflects
/// real broadcasts only.
#[derive(Clone)]
pub struct RelayHeartbeatSender {
    state: SharedState,
    /// `HeartbeatMonitor` address (canonical chain-40204 book).
    monitor: chainio::abi::Address,
    chain_id: u64,
}

impl RelayHeartbeatSender {
    pub fn new(state: SharedState, monitor: chainio::abi::Address, chain_id: u64) -> Self {
        Self {
            state,
            monitor,
            chain_id,
        }
    }
}

impl heartbeat::HeartbeatSender for RelayHeartbeatSender {
    async fn send_heartbeat(
        &self,
        calldata: &[u8],
    ) -> Result<heartbeat::SendOutcome, heartbeat::HeartbeatError> {
        self.state.write().await.enqueue_recurring_signature_request(
            lifecycle::WriteIntent::Heartbeat.label().to_string(),
            hex_encode(&self.monitor),
            hex_encode(calldata),
            0,
            self.chain_id,
            "heartbeat (provider liveness)".to_string(),
            0,
        );
        // Queued for the signing surface — liveness is recorded on observe.
        Ok(heartbeat::SendOutcome::Queued)
    }
}

/// Bid placer over the signing relay: a Bid decision enqueues the unsigned
/// `ComputeMarketplace.bidOnJob(jobId, price, latency)` write. Identical bid
/// params re-emitted next tick dedup by calldata (one-shot semantics — a bid,
/// unlike a heartbeat, must never re-arm once broadcast).
#[derive(Clone)]
pub struct RelayBidPlacer {
    signer: RelaySigner,
    /// `ComputeMarketplace` address (canonical chain-40204 book).
    marketplace: chainio::abi::Address,
    chain_id: u64,
}

impl RelayBidPlacer {
    pub fn new(
        state: SharedState,
        marketplace: chainio::abi::Address,
        chain_id: u64,
    ) -> Self {
        Self {
            signer: RelaySigner::new(state),
            marketplace,
            chain_id,
        }
    }
}

impl crate::daemon::BidPlacer for RelayBidPlacer {
    async fn place(
        &self,
        job_id: u128,
        price_wei: u128,
        estimated_latency_ms: u128,
    ) -> Result<(), String> {
        let req = SignatureRequest {
            intent: lifecycle::WriteIntent::BidOnJob,
            to: self.marketplace,
            calldata: chainio::marketplace::encode_bid_on_job(
                job_id,
                price_wei,
                estimated_latency_ms,
            ),
            value_wei: 0,
            chain_id: self.chain_id,
            context: format!("bidOnJob job {job_id} at {price_wei} wei"),
            expires_block: 0,
        };
        self.signer
            .request(req)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::BidPlacer;
    use heartbeat::HeartbeatSender;
    use lifecycle::WriteIntent;
    use std::sync::Arc;
    use supervision::AgentState;
    use tokio::sync::RwLock;

    fn req(calldata: Vec<u8>) -> SignatureRequest {
        SignatureRequest {
            intent: WriteIntent::StartExecution,
            to: [0x11; 20],
            calldata,
            value_wei: 0,
            chain_id: 40204,
            context: "startExecution job 7".into(),
            expires_block: 200,
        }
    }

    #[tokio::test]
    async fn relay_signer_enqueues_into_shared_state() {
        let state: SharedState = Arc::new(RwLock::new(AgentState::new()));
        let signer = RelaySigner::new(state.clone());

        signer.request(req(vec![0xaa, 0xbb])).await.unwrap();
        let reqs = state.read().await.signature_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].intent, "startExecution");
        assert_eq!(reqs[0].to, "0x1111111111111111111111111111111111111111");
        assert_eq!(reqs[0].calldata, "0xaabb");
        assert_eq!(reqs[0].status, "pending");

        // Same calldata re-emitted (next tick) → idempotent, still one entry.
        signer.request(req(vec![0xaa, 0xbb])).await.unwrap();
        assert_eq!(state.read().await.signature_requests().len(), 1);

        // A different write → a second entry.
        signer.request(req(vec![0xcc])).await.unwrap();
        assert_eq!(state.read().await.signature_requests().len(), 2);
    }

    #[tokio::test]
    async fn heartbeat_sender_enqueues_and_rearms_the_recurring_write() {
        let state: SharedState = Arc::new(RwLock::new(AgentState::new()));
        let sender = RelayHeartbeatSender::new(state.clone(), [0x22; 20], 40204);
        let cd = heartbeat::heartbeat_calldata();

        let out = sender.send_heartbeat(&cd).await.expect("queued");
        assert_eq!(out, heartbeat::SendOutcome::Queued);
        let reqs = state.read().await.signature_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].intent, "heartbeat");
        assert_eq!(reqs[0].to, "0x2222222222222222222222222222222222222222");
        assert_eq!(reqs[0].calldata, "0x3defb962");
        assert_eq!(reqs[0].value_wei, "0");
        assert_eq!(reqs[0].status, "pending");

        // Signed + observed → submitted; the NEXT beat re-arms the same entry.
        let id = reqs[0].id;
        state.write().await.mark_request_observed(id, "0xbeef".into());
        assert_eq!(state.read().await.signature_requests()[0].status, "submitted");
        sender.send_heartbeat(&cd).await.expect("re-armed");
        let reqs = state.read().await.signature_requests();
        assert_eq!(reqs.len(), 1, "recurring write never duplicates");
        assert_eq!(reqs[0].status, "pending");
        // And the observed heartbeat recorded liveness.
        assert!(state.read().await.health().heartbeat_age_secs.is_some());
    }

    #[tokio::test]
    async fn bid_placer_enqueues_bid_on_job_once() {
        let state: SharedState = Arc::new(RwLock::new(AgentState::new()));
        let placer = RelayBidPlacer::new(state.clone(), [0x11; 20], 40204);

        placer.place(7, 1_150_000, 600_000).await.expect("queued");
        let reqs = state.read().await.signature_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].intent, "bidOnJob");
        assert!(reqs[0].calldata.starts_with("0x18360fc2"), "pinned selector");
        assert_eq!(reqs[0].value_wei, "0");

        // Same bid re-emitted next tick → dedup, no duplicate.
        placer.place(7, 1_150_000, 600_000).await.expect("dedup");
        assert_eq!(state.read().await.signature_requests().len(), 1);

        // A bid, once observed, must NOT re-arm (one-shot semantics).
        let id = state.read().await.signature_requests()[0].id;
        state.write().await.mark_request_observed(id, "0xbeef".into());
        placer.place(7, 1_150_000, 600_000).await.expect("still submitted");
        assert_eq!(
            state.read().await.signature_requests()[0].status,
            "submitted"
        );
    }
}
