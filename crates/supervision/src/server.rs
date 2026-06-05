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

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
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
