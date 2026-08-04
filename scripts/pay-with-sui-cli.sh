#!/usr/bin/env bash
#
# Produce a REAL signed Sui payment and run it through the facilitator.
#
# This is the piece that makes `verification_mode: sui-grpc` testable at all:
# placeholder bytes fail signature verification by design, so exercising the
# real path needs a genuinely signed transaction. It uses the `sui` CLI and your
# active testnet wallet rather than embedding a keypair.
#
# By default it only calls /verify, which SIMULATES — no funds move. Pass
# --settle to actually broadcast.
#
# Prerequisites:
#   - `sui` CLI on testnet with USDC and a little SUI for gas
#   - at least two addresses (`sui client addresses`) so you can pay someone else
#   - the verifier running with verification_mode: sui-grpc and its
#     facilitator_api_listen_addr set
#
# Usage:
#   scripts/pay-with-sui-cli.sh [--settle] [--amount N] [--api URL]

set -euo pipefail

AMOUNT="${AMOUNT:-10}"          # base units; USDC has 6 decimals, so 10 = 0.00001
API="${API:-http://localhost:50052}"
SETTLE=0
USDC_TYPE="${USDC_TYPE:-0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC}"
NETWORK="${NETWORK:-sui:testnet}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --settle) SETTLE=1; shift ;;
    --amount) AMOUNT="$2"; shift 2 ;;
    --api)    API="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

command -v sui >/dev/null || { echo "!! the sui CLI is required" >&2; exit 1; }

SENDER=$(sui client active-address)

# Pay a *different* address you control. Paying yourself would net your balance
# change to roughly zero (minus gas), and the facilitator asserts the recipient
# is credited exactly `amount` — so a self-payment correctly fails.
PAYEE="${PAYEE:-$(sui client addresses --json 2>/dev/null | python3 -c "
import json,sys
data = json.load(sys.stdin)
rows = data['addresses'] if isinstance(data, dict) else data
active = sys.argv[1]
for row in rows:
    addr = row[1] if isinstance(row, list) else row.get('address')
    if addr and addr != active:
        print(addr); break
" "$SENDER")}"

if [[ -z "${PAYEE:-}" ]]; then
  echo "!! No second address found. Create one with: sui client new-address ed25519" >&2
  exit 1
fi

COIN=$(sui client balance --with-coins --json 2>/dev/null | python3 -c "
import json,sys
for group in json.load(sys.stdin):
    for entry in group:
        if '$USDC_TYPE' == entry['balance']['coinType']:
            print(entry['coins'][0]['coinObjectId']); raise SystemExit
")
if [[ -z "${COIN:-}" ]]; then
  echo "!! No USDC coin found. Fund this address at https://faucet.circle.com (Sui Testnet)." >&2
  exit 1
fi

echo "==> sender    $SENDER"
echo "==> payee     $PAYEE"
echo "==> amount    $AMOUNT base units of USDC"

# `pay` splits the input coin so the recipient is credited EXACTLY $AMOUNT,
# which is what the `exact` scheme requires.
TX=$(sui client pay \
      --input-coins "$COIN" \
      --recipients "$PAYEE" \
      --amounts "$AMOUNT" \
      --gas-budget 10000000 \
      --serialize-unsigned-transaction 2>&1 | tail -1)

SIG=$(sui keytool sign --address "$SENDER" --data "$TX" --json 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['suiSignature'])")

ENDPOINT="/verify"
[[ "$SETTLE" -eq 1 ]] && ENDPOINT="/settle"

echo "==> POST $API$ENDPOINT"
[[ "$SETTLE" -eq 1 ]] && echo "    (this BROADCASTS and moves real testnet USDC)"

TX="$TX" SIG="$SIG" PAYEE="$PAYEE" AMOUNT="$AMOUNT" \
USDC_TYPE="$USDC_TYPE" NETWORK="$NETWORK" API="$API" ENDPOINT="$ENDPOINT" \
python3 <<'PY'
import json, os, subprocess

req = {
    "scheme": "exact",
    "network": os.environ["NETWORK"],
    "amount": os.environ["AMOUNT"],
    "asset": os.environ["USDC_TYPE"],
    "payTo": os.environ["PAYEE"],
    "maxTimeoutSeconds": 60,
}
body = {
    "x402Version": 2,
    # The client echoes back the requirements it accepted; the facilitator
    # re-checks every field against what it advertised.
    "paymentPayload": {
        "x402Version": 2,
        "accepted": req,
        "payload": {"signature": os.environ["SIG"], "transaction": os.environ["TX"]},
    },
    "paymentRequirements": req,
}

out = subprocess.run(
    ["curl", "-s", "-X", "POST", os.environ["API"] + os.environ["ENDPOINT"],
     "-H", "content-type: application/json", "-d", json.dumps(body)],
    capture_output=True, text=True,
).stdout

print("<==", out)
try:
    parsed = json.loads(out)
except json.JSONDecodeError:
    raise SystemExit(1)

if parsed.get("isValid") or parsed.get("success"):
    payer = parsed.get("payer")
    print(f"    payer recovered from the signature: {payer}")
    print("    (not taken from any client-supplied field)")
else:
    reason = parsed.get("invalidReason") or parsed.get("errorReason")
    print(f"    refused: {reason}")
    raise SystemExit(1)
PY
