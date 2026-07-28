#!/usr/bin/env bash
# LOCAL address-drift check — no GitHub Actions, no PAT required.
#
# Compares this repo's vendored 40204 address book against the sibling
# citrate-chain canonical, using the @citratelabs/chain-config tool. Run this
# before pushing/merging (and after every re-roll) while org CI is unavailable.
#
#   bash scripts/check-address-drift.sh
#   CITRATE_CHAIN_DIR=/path/to/citrate-chain bash scripts/check-address-drift.sh
#
# Exit 1 on drift. This is the local mirror of .github/workflows/address-drift.yml
# (which runs the identical check once GitHub Actions + CITRATE_CHAIN_READ_TOKEN
# are available).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CHAIN="${CITRATE_CHAIN_DIR:-$HERE/../citrate-chain}"
TOOL="$CHAIN/packages/chain-config/bin/check.mjs"
CANON="$CHAIN/contracts/addresses/40204.json"
VENDORED="$HERE/crates/chainio/src/generated/addresses.json"
if [ ! -f "$TOOL" ]; then
  echo "[address-drift] citrate-chain not found at $CHAIN (set CITRATE_CHAIN_DIR)"; exit 2
fi
node "$TOOL" check "$VENDORED" --canonical "$CANON"
