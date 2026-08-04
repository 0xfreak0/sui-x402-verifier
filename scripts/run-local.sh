#!/usr/bin/env bash
#
# Bring up the verifier and Envoy together for local testing, then tear both
# down cleanly on Ctrl-C.
#
# Envoy is launched via func-e (https://func-e.io), which fetches a pinned
# Envoy binary on first run — no Docker required. Set ENVOY_BIN to use your own.
#
# Usage: scripts/run-local.sh [config.yaml]

set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="${1:-config.example.yaml}"
ENVOY_BIN="${ENVOY_BIN:-}"
LOG_DIR="${LOG_DIR:-./.local-logs}"

mkdir -p "$LOG_DIR"

# A throwaway key is fine locally, but generating one per run means a restart
# invalidates old session tokens — which is the correct production behavior too.
export X402_SESSION_HMAC_SECRET="${X402_SESSION_HMAC_SECRET:-$(openssl rand -hex 32)}"

# config.example.yaml ships the zero address, which the service refuses to start
# with. Supply a synthetic one for local runs; nothing settles in stub mode.
# Export your own X402_PAY_TO to receive real payments.
export X402_PAY_TO="${X402_PAY_TO:-0x$(printf '9%.0s' {1..64})}"

echo "==> Building verifier"
cargo build --quiet

echo "==> Starting verifier (logs: $LOG_DIR/verifier.log)"
RUST_LOG="${RUST_LOG:-x402_verifier=debug}" \
  ./target/debug/x402-verifier --config "$CONFIG" >"$LOG_DIR/verifier.log" 2>&1 &
VERIFIER_PID=$!

cleanup() {
  echo
  echo "==> Shutting down"
  kill "$VERIFIER_PID" 2>/dev/null || true
  kill "${ENVOY_PID:-}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for the gRPC port rather than sleeping a fixed amount.
for _ in $(seq 1 50); do
  nc -z 127.0.0.1 50051 2>/dev/null && break
  sleep 0.1
done

if ! kill -0 "$VERIFIER_PID" 2>/dev/null; then
  echo "!! verifier exited during startup:" >&2
  cat "$LOG_DIR/verifier.log" >&2
  exit 1
fi
echo "    verifier listening on 127.0.0.1:50051"

echo "==> Starting Envoy (logs: $LOG_DIR/envoy.log)"
if [[ -n "$ENVOY_BIN" ]]; then
  "$ENVOY_BIN" -c envoy.yaml >"$LOG_DIR/envoy.log" 2>&1 &
elif command -v envoy >/dev/null 2>&1; then
  envoy -c envoy.yaml >"$LOG_DIR/envoy.log" 2>&1 &
elif command -v func-e >/dev/null 2>&1; then
  func-e run -c envoy.yaml >"$LOG_DIR/envoy.log" 2>&1 &
else
  echo "!! No Envoy found. Install one of:" >&2
  echo "     curl -L https://func-e.io/install.sh | bash -s -- -b /usr/local/bin" >&2
  echo "     brew install envoy" >&2
  exit 1
fi
ENVOY_PID=$!

for _ in $(seq 1 100); do
  nc -z 127.0.0.1 10000 2>/dev/null && break
  sleep 0.1
done

if ! kill -0 "$ENVOY_PID" 2>/dev/null; then
  echo "!! Envoy exited during startup:" >&2
  tail -30 "$LOG_DIR/envoy.log" >&2
  exit 1
fi

cat <<'EOF'
    Envoy listening on 0.0.0.0:10000 (admin on 127.0.0.1:9901)

==> Ready. In another shell:

    scripts/e2e-test.sh

    # or by hand — the first 5 succeed, the 6th returns 402:
    curl -i -X POST localhost:10000/graphql \
      -H 'Content-Type: application/json' \
      -d '{"query":"{ chainIdentifier }"}'

Ctrl-C to stop.
EOF

wait
