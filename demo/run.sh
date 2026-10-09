#!/usr/bin/env bash
# Törus demo runner.
#   Local (default): starts a fresh local validator with both programs, runs the demo, cleans up.
#   Devnet: ANCHOR_PROVIDER_URL=https://api.devnet.solana.com ANCHOR_WALLET=<deployer keypair> demo/run.sh --links
# Programs run as upgradeable with the wallet as upgrade authority (initialize requires it).
set -euo pipefail
cd "$(dirname "$0")/.."

WALLET="${ANCHOR_WALLET:-$HOME/.config/solana/id.json}"
for f in target/idl/torus_protocol.json target/idl/torus_hook.json; do
  [[ -f "$f" ]] || { echo "missing $f — run 'anchor build' first"; exit 1; }
done

if [[ -n "${ANCHOR_PROVIDER_URL:-}" && "${ANCHOR_PROVIDER_URL}" != *127.0.0.1* && "${ANCHOR_PROVIDER_URL}" != *localhost* ]]; then
  ANCHOR_WALLET="$WALLET" TS_NODE_TRANSPILE_ONLY=1 npx ts-node -P tsconfig.json demo/demo.ts "$@"
  exit
fi

RPC_PORT="${RPC_PORT:-8899}"
PROTOCOL_ID="$(solana address -k target/deploy/torus_protocol-keypair.json)"
HOOK_ID="$(solana address -k target/deploy/torus_hook-keypair.json)"
for f in target/deploy/torus_protocol.so target/deploy/torus_hook.so; do
  [[ -f "$f" ]] || { echo "missing $f — run 'anchor build' first"; exit 1; }
done
if lsof -iTCP:"$RPC_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $RPC_PORT is already in use (another validator?). Stop it or set RPC_PORT."; exit 1
fi

LEDGER="$(mktemp -d -t torus-demo-ledger)"
solana-test-validator --reset --quiet --ledger "$LEDGER" \
  --rpc-port "$RPC_PORT" \
  --mint "$(solana address -k "$WALLET")" \
  --upgradeable-program "$PROTOCOL_ID" target/deploy/torus_protocol.so "$(solana address -k "$WALLET")" \
  --upgradeable-program "$HOOK_ID" target/deploy/torus_hook.so "$(solana address -k "$WALLET")" \
  >/dev/null 2>&1 &
VALIDATOR_PID=$!
cleanup() { kill "$VALIDATOR_PID" 2>/dev/null || true; wait "$VALIDATOR_PID" 2>/dev/null || true; rm -rf "$LEDGER"; }
trap cleanup EXIT

URL="http://127.0.0.1:$RPC_PORT"
for _ in $(seq 1 120); do
  solana cluster-version -u "$URL" >/dev/null 2>&1 && break
  sleep 0.5
done
solana cluster-version -u "$URL" >/dev/null 2>&1 || { echo "validator did not start"; exit 1; }
sleep 2 # the demo reads chain time; wait for the first timestamped blocks

ANCHOR_PROVIDER_URL="$URL" ANCHOR_WALLET="$WALLET" TS_NODE_TRANSPILE_ONLY=1 \
  npx ts-node -P tsconfig.json demo/demo.ts "$@"
