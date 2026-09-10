---
created: 2026-06-03T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: scaffold
planset: SELL
stage: Stage-3 SELL-S0/S1
repo: citrate-node-agent (NEW, Tier-1)
pins: citrate-chain canonical DEPLOYED_ADDRESSES.md (chain 40204)
---

# Agent entry — citrate-node-agent

This repo is the shared GPU **execution runtime** for the Citrate federation and
is part of the GTM-spine **SELL** planset (Stage-3 SELL-S0/S1 foundation work).

- **Design**: `citrate-federation/.agentile/gtm-spine/design/citrate-node-agent.md`
- **Canonical addresses**: pinned to `citrate-chain/contracts/DEPLOYED_ADDRESSES.md`
  (chain `40204`). The `chainio` crate mirrors that table; its
  `canonical_addresses` test is the divergence tripwire (Rule 11).
- **Rule 1**: only real, compiling crates ship — no empty stub crates/modules.
  `chainio` is the only crate today; the rest are roadmap (see `README.md`).
- **Rule 2**: tests exist and pass (`cargo test`).
