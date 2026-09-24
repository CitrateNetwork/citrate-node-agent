# citrate-node-agent

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*

> The GPU execution runtime for a single Citrate seller node — it reads your
> node settings, registers on the compute marketplace, bids cost-plus, runs real
> inference, proves and settles the result, and stays un-slashed (heartbeat +
> schedule safety), exposing a loopback supervision API the GUI drives.

## What it is

`citrate-node-agent` is the daemon that turns a machine with a GPU into a
marketplace seller on chain **40204**. It is a Rust workspace of small, honest
crates: `chainio` (the canonical address book + a minimal EVM JSON-RPC read
client and calldata builders), `config` (the `compute.json` reader), `bidder`
(pure cost-plus bid logic), `heartbeat` (anti-slash liveness), `supervision`
(the local HTTP control surface), and the `node-agent` binary that ties them
together. It reads chain truth over JSON-RPC — it has no Rust dependency on the
chain crates.

- Concept docs: https://docs.citrate.ai/compute · Selling: https://docs.citrate.ai/sell
- Depends on a local [citrate-chain](https://github.com/CitrateNetwork/citrate-chain)
  RPC + the deployed compute-marketplace contracts.

## Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# System packages (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y build-essential pkg-config git curl

# For real inference (SELL-S2+): a local llama-server (or compatible OpenAI
# HTTP endpoint) reachable over loopback, and a local IPFS/Kubo gateway for
# model-weight fetch. Both optional for the S1 config/bid self-check.
```

The pure-logic crates (`config`, `bidder`, `chainio` codec) build and test fully
offline with no system deps beyond a C toolchain.

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-node-agent
cd citrate-node-agent

cargo build --release        # produces target/release/node-agent
cargo test                   # unit tests; all run offline
```

The live-RPC integration tests skip cleanly unless you point them at a chain-40204
endpoint:

```bash
CITRATE_RPC_URL=http://localhost:8545 cargo test -p chainio -- --nocapture
```

## Run locally

The agent takes a `compute.json` settings file and, optionally, a job id. Create
a minimal `compute.json`:

```json
{ "enabled": true, "allocation_percent": 50, "schedule": [] }
```

Config self-check (offline — no chain reads):

```bash
./target/release/node-agent ./compute.json
```

Live one-shot against a local chain (evaluate a bid for job `0`):

```bash
CITRATE_RPC_URL=http://localhost:8545 ./target/release/node-agent ./compute.json 0
```

Daemon mode brings up the supervision HTTP surface (loopback only):

```bash
CITRATE_RPC_URL=http://localhost:8545 ./target/release/node-agent --daemon ./compute.json 0
```

Verify the supervision API — default bind `127.0.0.1:19600`:

```bash
curl -s http://127.0.0.1:19600/status     # -> "idle" | "bidding" | "executing" | "paused"
curl -s http://127.0.0.1:19600/health     # JSON health snapshot (Bearer token if configured)
```

## Connect it locally  ← the differentiator

The agent needs a **local chain RPC** (and, for execution, a local model backend
and IPFS gateway). Bring-up order:

1. Start a devnet node from
   [citrate-chain](https://github.com/CitrateNetwork/citrate-chain):
   `./target/release/citrate devnet` → RPC on `http://localhost:8545`.
2. Deploy the contract book there (`forge script script/Deploy.s.sol …`) so the
   ComputeMarketplace / ModelRegistry addresses in `chainio` resolve to live code.
3. Point the agent at the chain:
   ```bash
   export CITRATE_RPC_URL=http://localhost:8545
   # optional, for SELL-S2 execution:
   export CITRATE_LLAMA_URL=http://127.0.0.1:8181     # local llama-server / OpenAI-compatible
   export CITRATE_IPFS_GATEWAY=http://127.0.0.1:8080  # local Kubo gateway
   ./target/release/node-agent --daemon ./compute.json 0
   ```

**Outbound TLS policy:** every outbound endpoint (`CITRATE_RPC_URL`,
`CITRATE_IPFS_GATEWAY`, `CITRATE_LLAMA_URL`) must be `https://`, or plain `http://`
to a **loopback** host (`localhost` / `127.0.0.0/8` / `[::1]`). Anything else fails
closed at startup. For plaintext LAN test rigs only, the dev escape hatch
`CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1` re-enables plaintext to non-loopback
hosts (logged loudly). Never set it in production.

See the full multi-repo bring-up: https://docs.citrate.ai/local-stack

## Configuration

- `compute.json`: `{ enabled, allocation_percent, schedule }` — the node's opt-in,
  GPU allocation percentage, and the schedule windows during which it bids.
- Env vars:
  - `CITRATE_RPC_URL` — chain-40204 JSON-RPC (enables live reads; unset = config self-check only)
  - `CITRATE_LLAMA_URL`, `CITRATE_IPFS_GATEWAY` — inference + model-weight backends
  - `CITRATE_PROVIDER_ADDRESS` — this node's on-chain provider address (capacity caps)
  - `CITRATE_NODE_PFLOPS_1E18` — declared node throughput (default 6.0 pflops ×1e18)
  - `CITRATE_NODE_AGENT_ADDR` — supervision bind (default `127.0.0.1:19600`, loopback only)
  - `CITRATE_NODE_AGENT_DAEMON=1` — run in daemon mode without the `--daemon` flag

## Links

- Docs: https://docs.citrate.ai/compute
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) ·
  Consumed by: citrate-gui-native (GPU seller UI), the SELL planset
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)). This is the open-source infrastructure tier of Citrate's open-core model. The commercial application layer is source-available under BUSL-1.1. Licensor: Citrate Inc.
