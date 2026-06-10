//! `server` — the local HTTP supervision surface the GUI drives.
//!
//! Endpoints (all localhost-only):
//!   - `GET  /health`  → the [`Health`](crate::state::Health) JSON snapshot.
//!   - `GET  /status`  → a bare JSON string: `"idle"|"bidding"|"executing"|"paused"`.
//!   - `POST /pause`   → set paused (stop new bids, in-flight continue) → 200.
//!   - `POST /resume`  → clear paused → 200.
//!
//! The router is built over the shared [`SharedState`] so the daemon loop and
//! the handlers observe the same record. [`router`] is exposed separately from
//! [`serve`] so tests can mount it on an ephemeral port without committing to a
//! fixed address.
//!
//! ## SECREM-01 SVC-6 (pre-audit 2026-06-09): localhost-trust assumption
//!
//! This is an unauthenticated control surface — `/pause`, `/resume`, and the
//! signature-request endpoints mutate agent state and have NO per-request auth.
//! Its only access control is the loopback bind: any process able to reach
//! `127.0.0.1:19600` is trusted, on the assumption that it shares the node
//! operator's trust boundary (the local GUI / signing relay). That assumption
//! is enforced fail-closed in two places — [`resolve_addr`] and [`serve`] both
//! reject any non-loopback bind, so the env override cannot widen this surface
//! to `0.0.0.0` or a routable interface. If per-request auth is ever needed
//! (e.g. multi-tenant hosts), add it here; do NOT relax the loopback guard.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::state::AgentState;

/// The default localhost bind address (env `CITRATE_NODE_AGENT_ADDR` overrides).
pub const DEFAULT_ADDR: &str = "127.0.0.1:19600";

/// Env var that overrides the bind address.
pub const ADDR_ENV: &str = "CITRATE_NODE_AGENT_ADDR";

/// Shared agent state handle used by both the loop and the HTTP handlers.
pub type SharedState = Arc<RwLock<AgentState>>;

/// Resolve the bind address from `CITRATE_NODE_AGENT_ADDR` (falling back to
/// [`DEFAULT_ADDR`]). Returns an error if the env value can't be parsed, and
/// refuses any non-loopback address (the supervision surface is localhost-only).
pub fn resolve_addr() -> Result<SocketAddr, String> {
    let raw = std::env::var(ADDR_ENV).unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let addr: SocketAddr = raw
        .parse()
        .map_err(|e| format!("invalid {ADDR_ENV}={raw:?}: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "{ADDR_ENV}={raw:?} is not a loopback address; the supervision surface is localhost-only"
        ));
    }
    Ok(addr)
}

/// Build the supervision router over `state`.
pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .route("/signature-requests", get(list_signature_requests))
        .route("/signature-requests/:id/observed", post(observe_signature_request))
        .with_state(state)
}

/// `GET /health` → the full health snapshot.
async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    let snapshot = state.read().await.health();
    Json(snapshot)
}

/// `GET /status` → a bare JSON status string.
async fn status(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await.lifecycle();
    Json(s.as_str())
}

/// `POST /pause` → stop accepting new bids (in-flight jobs finish).
async fn pause(State(state): State<SharedState>) -> impl IntoResponse {
    state.write().await.pause();
    (StatusCode::OK, Json(state.read().await.lifecycle().as_str()))
}

/// `POST /resume` → resume bidding.
async fn resume(State(state): State<SharedState>) -> impl IntoResponse {
    state.write().await.resume();
    (StatusCode::OK, Json(state.read().await.lifecycle().as_str()))
}

/// `GET /signature-requests` → the unsigned chain writes the daemon needs signed.
/// The signing surface (gui-native / relay) fetches these, signs + broadcasts the
/// `pending` ones, and reports back via the observe endpoint.
async fn list_signature_requests(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.read().await.signature_requests())
}

/// Body of `POST /signature-requests/{id}/observed`.
#[derive(Deserialize)]
struct ObserveBody {
    /// The broadcast transaction hash.
    tx_hash: String,
}

/// `POST /signature-requests/{id}/observed` → mark a request signed + broadcast.
/// 200 on success; 404 if the id is unknown.
async fn observe_signature_request(
    State(state): State<SharedState>,
    Path(id): Path<u64>,
    Json(body): Json<ObserveBody>,
) -> impl IntoResponse {
    if state.write().await.mark_request_observed(id, body.tx_hash) {
        (StatusCode::OK, Json("observed"))
    } else {
        (StatusCode::NOT_FOUND, Json("unknown request id"))
    }
}

/// Bind the supervision server to `addr` (must be loopback) and serve until the
/// process exits. Returns an error if binding fails or `addr` is non-loopback.
pub async fn serve(addr: SocketAddr, state: SharedState) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind supervision server to non-loopback {addr}"
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("binding supervision server to {addr}: {e}"))?;
    axum::serve(listener, router(state))
        .await
        .map_err(|e| format!("supervision server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> SharedState {
        Arc::new(RwLock::new(AgentState::new()))
    }

    /// Spawn the server on an ephemeral loopback port; return its address.
    async fn spawn(state: SharedState) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    // NOTE: `resolve_addr` reads a process-global env var, so all of its cases
    // live in ONE test to avoid the parallel-test env-var race (cargo runs the
    // crate's tests concurrently within a single process).
    #[test]
    fn resolve_addr_default_loopback_and_rejections() {
        // Default (env unset) → 127.0.0.1:19600.
        std::env::remove_var(ADDR_ENV);
        let addr = resolve_addr().unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 19600);

        // A custom loopback port is honored.
        std::env::set_var(ADDR_ENV, "127.0.0.1:25000");
        let addr = resolve_addr().unwrap();
        assert_eq!(addr.port(), 25000);
        assert!(addr.ip().is_loopback());

        // Non-loopback is refused.
        std::env::set_var(ADDR_ENV, "0.0.0.0:19600");
        assert!(resolve_addr().unwrap_err().contains("loopback"));

        // Garbage is refused.
        std::env::set_var(ADDR_ENV, "not-an-addr");
        assert!(resolve_addr().unwrap_err().contains("invalid"));

        std::env::remove_var(ADDR_ENV);
    }

    #[tokio::test]
    async fn serve_refuses_non_loopback_bind() {
        let err = serve("8.8.8.8:19600".parse().unwrap(), shared())
            .await
            .unwrap_err();
        assert!(err.contains("non-loopback"), "err was: {err}");
    }

    #[tokio::test]
    async fn status_endpoint_reports_idle_then_paused() {
        let state = shared();
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // /status → "idle"
        let s: String = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(s, "idle");

        // POST /pause → 200, state→paused
        let r = client.post(format!("{base}/pause")).send().await.unwrap();
        assert_eq!(r.status(), 200);

        let s: String = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(s, "paused");
        // And the shared state actually rejects new bids now.
        assert!(!state.read().await.accepts_new_bids());
    }

    #[tokio::test]
    async fn pause_then_resume_round_trip() {
        let state = shared();
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        client.post(format!("{base}/pause")).send().await.unwrap();
        assert!(state.read().await.is_paused());

        let r = client.post(format!("{base}/resume")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(!state.read().await.is_paused());

        let s: String = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(s, "idle");
    }

    #[tokio::test]
    async fn health_endpoint_shape() {
        let state = shared();
        {
            let mut w = state.write().await;
            w.set_provider_stats(10, 9230);
            w.set_active_jobs(2);
            w.record_heartbeat();
        }
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let v: serde_json::Value = client
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(v["state"], "executing"); // 2 jobs in flight
        assert_eq!(v["active_jobs"], 2);
        assert_eq!(v["max_concurrent"], 10);
        assert_eq!(v["reputation_bps"], 9230);
        // heartbeat_age_secs is present (just recorded → small).
        assert!(v["heartbeat_age_secs"].is_number());
        // no error → field omitted.
        assert!(v.get("last_error").is_none());
    }

    #[tokio::test]
    async fn signature_requests_list_and_observe_roundtrip() {
        let state = shared();
        let id = {
            let mut w = state.write().await;
            w.enqueue_signature_request(
                "startExecution".into(),
                "0x11".into(),
                "0xaaaa".into(),
                0,
                40204,
                "startExecution job 7".into(),
                200,
            )
        };
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // GET → one pending request.
        let v: serde_json::Value = client
            .get(format!("{base}/signature-requests"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["intent"], "startExecution");
        assert_eq!(v[0]["status"], "pending");
        assert_eq!(v[0]["value_wei"], "0");

        // POST observed → 200; status flips to submitted.
        let r = client
            .post(format!("{base}/signature-requests/{id}/observed"))
            .json(&serde_json::json!({ "tx_hash": "0xdead" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(state.read().await.signature_requests()[0].status, "submitted");

        // Unknown id → 404.
        let r = client
            .post(format!("{base}/signature-requests/999/observed"))
            .json(&serde_json::json!({ "tx_hash": "0x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn health_reports_paused_state_with_inflight_jobs() {
        let state = shared();
        {
            let mut w = state.write().await;
            w.set_active_jobs(1);
        }
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        client.post(format!("{base}/pause")).send().await.unwrap();

        let v: serde_json::Value = client
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // Paused, but the in-flight job is still counted (it finishes).
        assert_eq!(v["state"], "paused");
        assert_eq!(v["active_jobs"], 1);
    }
}
