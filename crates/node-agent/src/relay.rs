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

#[cfg(test)]
mod tests {
    use super::*;
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
}
