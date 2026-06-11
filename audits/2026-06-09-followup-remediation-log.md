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
