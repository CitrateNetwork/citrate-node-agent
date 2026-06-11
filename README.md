# citrate-node-agent

The shared **GPU execution runtime** for the Citrate federation — drives safe,
profitable, automatic marketplace participation for single-node sellers
(gui-native) and pools (compute-pool). Part of the GTM-spine **SELL** planset
(Stage-3 SELL-S0/S1 foundation).

It reads node settings, registers, bids (cost-plus), runs real inference,
proves results (Commitment tier first), settles, and stays un-slashed
(heartbeat + schedule safety), exposing a supervision API the GUI drives.

## Design

See the canonical design doc:
`citrate-federation/.agentile/gtm-spine/design/citrate-node-agent.md`.

Chain addresses are sourced from the canonical `citrate-chain`
`contracts/DEPLOYED_ADDRESSES.md` (chain **40204**, testnet-beta) and mirrored
into the `chainio` crate. The `chainio::tests::canonical_addresses` test is the
divergence tripwire (federation Rule 11): if a chain re-roll moves an address,
re-mirror the book and update the test in the same change.

## Build & test

```bash
cargo build
cargo test
```

The pure-logic crates (`config`, `bidder`, and the `chainio` ABI/selectors)
build and test fully offline. The `chainio` JSON-RPC read client adds a minimal
well-known stack (`reqwest` + `tokio` + `serde_json` + `tiny-keccak`); its unit
tests still run offline, and the live-RPC integration tests
(`crates/chainio/tests/live_rpc.rs`) skip cleanly unless `CITRATE_RPC_URL`
points at a chain-40204 endpoint:

```bash
CITRATE_RPC_URL=<chain-40204 rpc> cargo test -p chainio -- --nocapture
```

Run the agent (offline config self-check, or live reads with `CITRATE_RPC_URL`):

```bash
node-agent path/to/compute.json [job-id]
```

### Outbound TLS policy (FUA-NODE-AGENT-06)

Every outbound endpoint the agent talks to — `CITRATE_RPC_URL`,
`CITRATE_IPFS_GATEWAY`, `CITRATE_LLAMA_URL` — must be `https://`, or plain
`http://` to a **loopback** host only (`localhost` / `127.0.0.0/8` / `[::1]`,
the local-Kubo / resident-llama-server posture). Anything else fails closed at
startup with a clear error. For plaintext LAN test rigs only, the **dev-only**
escape hatch `CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1` re-enables
plaintext to non-loopback hosts (logged loudly on every use). Never set it in
production: a MITM between the agent and its RPC can feed false chain-truth
(job state, the `committed` gate, oracle price). On-chain model CIDs are also
shape-validated as bare CIDv0/CIDv1 identifiers before any gateway URL is
built (FUA-NODE-AGENT-05).

## Crate layout (roadmap)

This repo ships only what is real and compiles — no empty stub crates
(federation Rule 1). New crates land as their SELL stage is implemented.

- **chainio** — *shipped (S0/S1).* Canonical chain-40204 address book +
  EVM JSON-RPC read client (`eth_call`/`eth_getCode`/`eth_chainId`), a minimal
  ABI codec, pinned function selectors, and typed `getProvider` / `getJob` /
  `saltPerPflopHour` decode + write-calldata builders.
- **config** — *shipped (S1).* `compute.json` reader
  (`{ enabled, allocation_percent, schedule }`) + schedule-window logic.
- **bidder** — *shipped (S1).* Pure cost-plus `evaluate(job, oracle, settings,
  caps) -> BidDecision`: `enabled`/schedule/Commitment-cap (`< 10 SALT`)/
  capacity (`< 80%`)/deadline gating, then `cost × 1.15` capped at 90% of
  `maxPrice`. Unit-tests every SELL-S1 scenario.
- **heartbeat** — *shipped (S1).* `HeartbeatMonitor.heartbeat()` calldata + a
  30s liveness loop behind a `HeartbeatSender` trait (anti-slash).
- **node-agent** — *shipped (S1).* Binary tying `compute.json` → clock → live
  chain reads → the bidder decision.
- **lifecycle** — *S2.* The on-chain job state machine:
  `startExecution → submitCommitment → submitResult → completeJob`
  (calldata builders already in `chainio::marketplace`).
- **executor** — *S2.* Model provisioning (ModelRegistry CID → IPFS fetch →
  SHA3 verify → cache), inference runtime adapter (`trait Inference`), and
  Commitment proof (`trait ProofMaker`; ZK/TEE behind a feature flag in S5).
- **schedule** — *S3.* Allocation enforcement
  (Linux cgroup v2 + `nvidia-smi`; macOS/Windows advisory).
- **earnings** — *S2.* Claimable poll + auto `claimRewards` over
  `ContributionAccounting`.
- **supervision** — *S1+.* Local HTTP control surface
  (`/health` `/status` `/pause` `/resume`) the GUI drives.

## Build order (maps to SELL-Sn)

S0 (address verify — this crate) → S1 MVP (register/bid/heartbeat/supervision/
Commitment-cap) → S2 execution (provision/infer/prove/claim) → S3
schedule-safety + dashboards → S4 cross-platform allocation → S5 ZK/TEE
(flagged) → S6 pool membership.

## License

Apache-2.0.
