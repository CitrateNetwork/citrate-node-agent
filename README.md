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

Pure-`std`, no external dependencies (S0/S1).

```bash
cargo build
cargo test
```

## Crate layout (roadmap)

This repo ships only what is real and compiles — no empty stub crates
(federation Rule 1). New crates land as their SELL stage is implemented.

- **chainio** — *shipped (S0).* Canonical chain-40204 address book +
  (future) marketplace / pool / oracle / heartbeat clients and ABIs.
- **bidder** — *S1.* Cost-plus strategy over `ComputePricingOracle` + score
  model, with caps and tier filtering.
- **lifecycle** — *S1/S2.* The on-chain job state machine:
  `startExecution → submitCommitment → submitResult → completeJob`.
- **executor** — *S2.* Model provisioning (ModelRegistry CID → IPFS fetch →
  SHA3 verify → cache), inference runtime adapter (`trait Inference`), and
  Commitment proof (`trait ProofMaker`; ZK/TEE behind a feature flag in S5).
- **heartbeat** — *S1.* `HeartbeatMonitor.heartbeat()` loop and suspension
  watch (anti-slash).
- **schedule** — *S3.* Window gate + allocation enforcement
  (Linux cgroup v2 + `nvidia-smi`; macOS/Windows advisory).
- **earnings** — *S2.* Claimable poll + auto `claimRewards` over
  `ContributionAccounting`.
- **supervision** — *S1.* Local HTTP control surface
  (`/health` `/status` `/pause` `/resume`) the GUI drives.

## Build order (maps to SELL-Sn)

S0 (address verify — this crate) → S1 MVP (register/bid/heartbeat/supervision/
Commitment-cap) → S2 execution (provision/infer/prove/claim) → S3
schedule-safety + dashboards → S4 cross-platform allocation → S5 ZK/TEE
(flagged) → S6 pool membership.

## License

Apache-2.0.
