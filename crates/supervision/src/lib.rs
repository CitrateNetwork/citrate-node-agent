//! `supervision` — the local HTTP control surface + agent state machine the
//! GUI drives (SELL-S1 supervision slice).
//!
//! Two pieces:
//!   - [`state`] — [`AgentState`](state::AgentState), the single shared,
//!     observable state record (lifecycle, heartbeat age, active jobs,
//!     reputation, last error) with real pause/resume semantics.
//!   - [`server`] — an `axum` router + `serve` that exposes `/health`,
//!     `/status`, `/pause`, `/resume` on a **loopback-only** address
//!     (`CITRATE_NODE_AGENT_ADDR`, default `127.0.0.1:19600`).
//!
//! The daemon loop (in the `node-agent` binary) owns an
//! `Arc<RwLock<AgentState>>`, mutates it each tick, and serves the same handle
//! to [`server::serve`]. There is no chain/ABI/key coupling here: the loop feeds
//! primitives in; the GUI reads snapshots out.

pub mod auth;
pub mod server;
pub mod state;

pub use auth::{default_token_path, SupervisionAuth, TOKEN_PATH_ENV};
pub use server::{resolve_addr, router, serve, SharedState, ADDR_ENV, DEFAULT_ADDR};
pub use state::{AgentState, Health, LifecycleState, PendingSignatureRequest};
