//! `server` — the local HTTP supervision surface the GUI drives.
//!
//! Endpoints (all localhost-only):
//!   - `GET  /health`  → the [`Health`](crate::state::Health) JSON snapshot, with
//!     `last_error` redacted to a fixed marker (it is unauthenticated — NA-02).
//!   - `GET  /health/detail` → the same snapshot with the real `last_error`
//!     (bearer-gated).
//!   - `GET  /status`  → a bare JSON string: `"idle"|"bidding"|"executing"|"paused"`.
//!   - `POST /pause`   → set paused (stop new bids, in-flight continue) → 200.
//!   - `POST /resume`  → clear paused → 200.
//!
//! The router is built over the shared [`SharedState`] so the daemon loop and
//! the handlers observe the same record. [`router`] is exposed separately from
//! [`serve`] so tests can mount it on an ephemeral port without committing to a
//! fixed address.
//!
//! ## Access control (SECREM-02 FUA-NODE-AGENT-01/02; SECREM-01 SVC-6)
//!
//! Two layers, both fail-closed:
//!   1. **Loopback bind** — [`resolve_addr`] and [`serve`] reject any
//!      non-loopback address, so the `CITRATE_NODE_AGENT_ADDR` override cannot
//!      widen this surface to `0.0.0.0` or a routable interface.
//!   2. **Per-instance bearer token** ([`crate::auth`]) — every endpoint except
//!      `/health` requires `Authorization: Bearer <token>` matching the token
//!      minted at startup and persisted `0600`. This closes the residual hole
//!      the loopback bind left open: an unprivileged local process (can't read
//!      the `0600` token file) and a web page the operator visits (can't read a
//!      local file, and the token defeats the no-preflight `/pause`/`/resume`
//!      CSRF) are both shut out. The signing surface (gui-native) reads the same
//!      file and presents the token.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::auth::SupervisionAuth;
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

/// Token-gate middleware (FUA-NODE-AGENT-01/02). Every protected endpoint must
/// present `Authorization: Bearer <token>` matching the per-instance supervision
/// token. A browser cannot read the `0600` token file, so this also closes the
/// no-preflight CSRF on `/pause` `/resume`; an unprivileged local process cannot
/// read the daemon-owned token file either. `/health` is intentionally left open
/// for liveness probes (it exposes no secret).
async fn require_token(
    State(auth): State<SupervisionAuth>,
    req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match presented {
        Some(tok) if auth.verify(tok) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json("missing or invalid supervision token"),
        )
            .into_response(),
    }
}

/// Build the supervision router over `state`, gating every endpoint except
/// `/health` behind the per-instance bearer token in `auth`.
pub fn router(state: SharedState, auth: SupervisionAuth) -> Router {
    let protected = Router::new()
        .route("/health/detail", get(health_detail))
        .route("/status", get(status))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .route("/signature-requests", get(list_signature_requests))
        .route("/signature-requests/:id/observed", post(observe_signature_request))
        .route_layer(middleware::from_fn_with_state(auth, require_token));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}

/// Marker the open `/health` shows in place of the real error text.
pub const REDACTED_LAST_ERROR: &str = "error recorded; details on authenticated GET /health/detail";

/// `GET /health` → the health snapshot for unauthenticated liveness probes.
///
/// PBA-L6b-039 / NA-02: `last_error` carries raw error text (RPC URLs, local
/// file paths, job ids). `/health` is deliberately open, so it only signals
/// THAT an error was recorded; the text is on the token-gated
/// `/health/detail`.
async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    let mut snapshot = state.read().await.health();
    if snapshot.last_error.is_some() {
        snapshot.last_error = Some(REDACTED_LAST_ERROR.to_string());
    }
    Json(snapshot)
}

/// `GET /health/detail` (bearer-gated) → the full snapshot incl. `last_error`.
async fn health_detail(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.read().await.health())
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
pub async fn serve(
    addr: SocketAddr,
    state: SharedState,
    auth: SupervisionAuth,
) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind supervision server to non-loopback {addr}"
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("binding supervision server to {addr}: {e}"))?;
    axum::serve(listener, router(state, auth))
        .await
        .map_err(|e| format!("supervision server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> SharedState {
        Arc::new(RwLock::new(AgentState::new()))
    }

    /// The known token every spawned test server is built with.
    const TEST_TOKEN: &str = "test-supervision-token-0123456789";
    fn test_auth() -> SupervisionAuth {
        SupervisionAuth::from_token(TEST_TOKEN)
    }

    /// A reqwest client that sends the correct bearer token on every request
    /// (so the existing functional tests exercise the authenticated path).
    fn authed_client() -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {TEST_TOKEN}").parse().unwrap(),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap()
    }

    /// Spawn the server (gated by [`test_auth`]) on an ephemeral loopback port.
    async fn spawn(state: SharedState) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state, test_auth());
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
        let err = serve("8.8.8.8:19600".parse().unwrap(), shared(), test_auth())
            .await
            .unwrap_err();
        assert!(err.contains("non-loopback"), "err was: {err}");
    }

    #[tokio::test]
    async fn status_endpoint_reports_idle_then_paused() {
        let state = shared();
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = authed_client();

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
        let client = authed_client();

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
        let client = authed_client();

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
        let client = authed_client();

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
        let client = authed_client();

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

    // ── FUA-NODE-AGENT-01/02: the bearer-token gate ──────────────────────────

    #[tokio::test]
    async fn protected_endpoints_reject_a_missing_token() {
        let state = shared();
        {
            // Enqueue a write so the read endpoint has the pre-reveal secret to leak.
            let mut w = state.write().await;
            w.enqueue_signature_request(
                "submitResult".into(),
                "0x11".into(),
                "0xCAFEBABE_secret_commitment".into(),
                0,
                40204,
                "submitResult job 1".into(),
                200,
            );
        }
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let anon = reqwest::Client::new(); // NO Authorization header

        // The secret-bearing read endpoint must NOT serve an unauthenticated caller.
        let r = anon.get(format!("{base}/signature-requests")).send().await.unwrap();
        assert_eq!(r.status(), 401);

        // State-changing endpoints likewise refuse (closes the /pause /resume CSRF).
        assert_eq!(anon.post(format!("{base}/pause")).send().await.unwrap().status(), 401);
        assert_eq!(anon.post(format!("{base}/resume")).send().await.unwrap().status(), 401);
        let r = anon
            .post(format!("{base}/signature-requests/1/observed"))
            .json(&serde_json::json!({ "tx_hash": "0xdead" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        // The poison-the-queue write never landed: the request is still pending.
        assert_eq!(state.read().await.signature_requests()[0].status, "pending");
    }

    #[tokio::test]
    async fn protected_endpoints_reject_a_wrong_token() {
        let state = shared();
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let r = client
            .get(format!("{base}/signature-requests"))
            .bearer_auth("not-the-right-token-000000000000")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    // PBA-L6b-039 / NA-02: the unauthenticated /health must not leak the raw
    // last_error text (RPC URLs, file paths, job ids); the full snapshot is on
    // the token-gated /health/detail.
    #[tokio::test]
    async fn l6b_039_open_health_redacts_last_error_detail_is_gated() {
        let state = shared();
        state
            .write()
            .await
            .set_last_error(Some("reading /home/op/secret-path/9.bin: boom".into()));
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let anon = reqwest::Client::new();

        let body = anon
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            !body.contains("secret-path"),
            "NA-02: open /health leaked the error detail: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["last_error"].is_string(), "an error is still signalled: {body}");

        let r = anon.get(format!("{base}/health/detail")).send().await.unwrap();
        assert_eq!(r.status(), 401, "detail requires the bearer token");
        let v: serde_json::Value = authed_client()
            .get(format!("{base}/health/detail"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["last_error"], "reading /home/op/secret-path/9.bin: boom");
    }

    #[tokio::test]
    async fn health_is_open_without_a_token() {
        // Liveness probes must work unauthenticated; /health exposes no secret.
        let state = shared();
        let addr = spawn(state.clone()).await;
        let base = format!("http://{addr}");
        let anon = reqwest::Client::new();

        let r = anon.get(format!("{base}/health")).send().await.unwrap();
        assert_eq!(r.status(), 200);
    }
}
