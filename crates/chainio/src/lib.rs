//! `chainio` — canonical chain-40204 address book + a minimal EVM JSON-RPC
//! read client for the Citrate node agent.
//!
//! Modules:
//! - [`addrbook`] — the canonical chain-40204 contract address book (mirrored
//!   from `citrate-chain` `DEPLOYED_ADDRESSES.md`, with a divergence tripwire).
//! - [`abi`]      — minimal ABI encode/decode for the static-typed READ calls
//!   the agent makes (`uint256`/`address`/`bool` words + tuple decoding).
//! - [`selectors`] — hand-derived 4-byte function selectors, each pinned by a
//!   unit test so a contract ABI change can't silently drift the agent.
//! - [`rpc`]      — a tiny `eth_call` client over JSON-RPC (reqwest + tokio).
//! - [`marketplace`] — typed wrappers that encode/decode the specific READ
//!   calls SELL-S1 needs: `getProvider`, `getJob`, `saltPerPflopHour`.

pub mod abi;
pub mod accounting;
pub mod addrbook;
pub mod marketplace;
pub mod model_registry;
pub mod rpc;
pub mod selectors;

// Re-export the address-book surface at the crate root so existing callers and
// the canonical-address tripwire keep their `chainio::compute_marketplace()`
// style paths.
pub use addrbook::*;
