---
created: 2026-06-10T00:00:00Z
branch: audit/secrem02-signing-seam
author: Fable 5 (Claude Code)
sprint: SECREM-02-followup-remediation
status: active
repo: citrate-node-agent
baseline_test_count: 187
---

# citrate-node-agent — SECREM-02 Remediation Log

> Coverage matrix: `citrate-security/planset/2026-06-10-followup-remediation.md`.
> This repo is one half of the **Phase-2 signing seam** (the other is
> citrate-gui-native); the per-instance bearer token below is the shared keystone.
> Protocol: re-verify → red test → fail-closed fix → suite green → mutation pass.

## Phase 2 — signing-seam (node-agent side)

| Finding | Sev | WP | Red test(s) | Fix | Suite | Mutation | Disposition |
|---|---|---|---|---|---|---|---|
| FUA-NODE-AGENT-01 | High | 2.1 | `server.rs::protected_endpoints_reject_a_missing_token` / `…_wrong_token`; `auth.rs` unit tests | New `auth.rs`: per-instance 256-bit CSPRNG token, persisted `0600`, constant-time verify; `require_token` middleware gates every endpoint except `/health`; `serve`/`router` take `SupervisionAuth`; daemon `load_or_create`s it — `crates/supervision/src/{auth.rs,server.rs,lib.rs}`, `crates/node-agent/src/main.rs` | supervision 30 (was ~24) ✓ | killed (bypass `auth.verify` → 2 gate tests FAIL) | **FIXED** |
| FUA-NODE-AGENT-02 | Med | 2.1 | `protected_endpoints_reject_a_missing_token` (covers `/pause` `/resume`) | Subsumed by the token gate: `/pause` `/resume` now require the bearer token, which a browser cannot read — closes the no-preflight CSRF | 30 ✓ | as above | **FIXED** |
| FUA-NODE-AGENT-04 | Med | 4.3 | (real-HTTP test = follow-up) | `IpfsGatewaySource::fetch` rejects an oversized Content-Length, then streams with a running `max_bytes` cap (`CITRATE_MAX_WEIGHT_BYTES`, default 8 GiB) — a malicious gateway can no longer OOM/disk-fill the daemon before the digest check — `crates/executor/src/models.rs` | build-verified | **FIXED (Phase 4.3)** |
| FUA-NODE-AGENT-03/05/06 | Low/Med | 4.3/7.4 | — | Weight integrity / CID / TLS — Phase 4.3 / 7.4 | — | — | OPEN (later phase) |

## Notes
- Baseline (Phase 0): node-agent workspace **187**; the supervision crate went
  **~24 → 30** (+4 auth unit tests, +3 server gate tests, with the `/health`-open
  test). Whole-workspace count only increases (Rule 2).
- New deps (already in lockfile): `getrandom = "0.2"`, `subtle = "2"`.
- **Shared contract with gui-native:** token file at `CITRATE_NODE_AGENT_TOKEN_FILE`
  (env) or `$HOME/.citrate/node-agent/supervision.token`, mode `0600`. gui-native
  reads the same path and presents `Authorization: Bearer <token>`.
- `/health` is intentionally left **open** (liveness probe; exposes no secret).
- Mutation: bypassing `auth.verify` in `require_token` fails the gate tests
  (`cargo-mutants` automation = Phase-8 follow-up).
- The "opaque handle instead of raw calldata" idea from the audit does not fit the
  architecture — the signing surface must see the calldata to sign it; the token
  gate is the correct control (only the token-holding GUI can read the queue).
- Branch: `audit/secrem02-signing-seam` (one commit spans node-agent + gui-native).

## Phase 7.4 — outbound hardening (FUA-NODE-AGENT-05 / FUA-NODE-AGENT-06) — 2026-06-11

> Branch `audit/secrem02-outbound-hardening`. Protocol: baseline → re-verify →
> red → fail-closed fix → green (count >= baseline) → mutation → log.

| Finding | Sev | Red test(s) | Fix | Suite | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-NODE-AGENT-05 | Low | `models.rs::malformed_cid_is_rejected_before_fetch` (pre-fix: `../../../api/v0/shutdown` ACCEPTED as ipfsCID when a digest is supplied); `…::gateway_source_refuses_non_cid_before_url_construction` (pre-fix the built URL was literally `http://127.0.0.1:1/api/v0/shutdown` — the on-chain CID's `../..` escaped `/ipfs/`) | New `executor::models::validate_cid` — accepts only a bare CIDv0 (`Qm` + 44 base58btc) or CIDv1 multibase-`b` base32lower decoding canonically to version 0x01; gated in `provision()` (new `ProvisionError::InvalidCid`, before any fetch) AND in `IpfsGatewaySource::fetch` (defense in depth at the URL-construction site). Traversal/`?`/`#`/`%2f`/alphabet/length/multibase violations all refused fail-closed | executor 22→27 ✓ | killed (`validate_cid` → `true`: 3 tests FAIL incl. both red tests) | **FIXED** |
| FUA-NODE-AGENT-06 | Low | `chainio::outbound` red stage = tests-only module → E0425/E0433 (validator absent) + E0599 (`RpcClient::new` infallible — plaintext remote accepted); executor red via new constructor tests | New `chainio::outbound::validate_outbound_url[_with]` (mirrors the supervision loopback gate from WP 2.1): `https://` any host; `http://` loopback only (`localhost`/`127.0.0.0/8`/`[::1]`); userinfo/empty-host/odd-scheme/portless-garbage → fail closed. Wired fail-closed into **construction** of all three outbound clients: `RpcClient::new`, `IpfsGatewaySource::new`, `LlamaServerInference::new` now return `Result` (callers in `main.rs`/tests updated). Dev-only escape hatch `CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1` (loud SECURITY log per use), documented dev-only in README + main.rs env docs | chainio 51→58 ✓; workspace 193→205, 0 failed | killed (`validate_outbound_url_with` → `Ok(())`: 4 tests FAIL incl. the `RpcClient` wiring test) | **FIXED** |

### Notes (7.4)
- **Baseline repair (deviation):** `cargo test --workspace` was RED on main before
  this WP — `abi::tests::address_from_hex_parses_canonical` still asserted the
  pre-reroll `0xf3..b6` bytes after commit `7b86fb8` swapped the literal to
  `0xc12d..373c`, and the failure blocked every downstream crate's tests. Fixed
  first as its own commit (test-only); true baseline after repair: **193 passed /
  0 failed** across 18 test binaries.
- **Deviation:** the WP brief cited a `validate_node_agent_url` precedent from
  WP 2.1 — no such symbol exists in this repo (WP 2.1 here was the bearer-token
  gate). Mirrored the closest precedent instead: the supervision server's
  fail-closed loopback gate (`server.rs::resolve_addr`/`serve`).
- TLS red stage is compile-stage red by necessity (the seam is new API +
  constructor signature change); the CID red stage is true assertion-red.
- The escape-hatch env path is covered via the pure `_with(allow_insecure)`
  core; tests do not mutate process env (parallel-test safety).
- Final: workspace **205 passed / 0 failed** (baseline 193; +12 security tests).
  Clippy: no new warnings (3 pre-existing in untouched `addrbook.rs`/`config`).
- FUA-NODE-AGENT-03 (UnixFS CID recompute / local-Kubo TCB doc) remains OPEN —
  not in this WP's scope; SVC-2 digest gating already bounds it.
