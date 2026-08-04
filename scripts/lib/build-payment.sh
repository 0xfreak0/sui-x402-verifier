#!/usr/bin/env bash
#
# Shared helper: build a base64 x402 PAYMENT-SIGNATURE header value.
#
# Two modes, because the two verification modes need genuinely different inputs:
#
#   placeholder  Structurally valid but unsigned bytes. Accepted only by
#                verification_mode: stub-accept-all.
#   real         A transaction built and signed by the local `sui` CLI wallet.
#                Required by verification_mode: sui-grpc, which checks the
#                signature and simulates the transfer.
#
# Usage:  build_payment <mode> <network> <amount> <asset> <pay_to>
# Echoes the base64 header value on stdout.

build_payment() {
  local mode="$1" network="$2" amount="$3" asset="$4" pay_to="$5"
  local tx sig

  if [[ "$mode" == "real" ]]; then
    command -v sui >/dev/null || {
      echo "!! --real needs the sui CLI on PATH" >&2
      return 1
    }

    local sender coin
    sender=$(sui client active-address)
    coin=$(sui client balance --with-coins --json 2>/dev/null | python3 -c "
import json,sys
want = sys.argv[1]
for group in json.load(sys.stdin):
    for entry in group:
        if entry['balance']['coinType'] == want:
            print(entry['coins'][0]['coinObjectId']); raise SystemExit
" "$asset")

    if [[ -z "${coin:-}" ]]; then
      echo "!! no $asset coin in $sender — fund it at https://faucet.circle.com" >&2
      return 1
    fi

    # `pay` splits the coin so the recipient is credited EXACTLY `amount`,
    # which is what the exact scheme requires and what step 4 asserts.
    tx=$(sui client pay --input-coins "$coin" --recipients "$pay_to" \
           --amounts "$amount" --gas-budget 10000000 \
           --serialize-unsigned-transaction 2>&1 | tail -1)
    sig=$(sui keytool sign --address "$sender" --data "$tx" --json 2>/dev/null \
           | python3 -c "import json,sys; print(json.load(sys.stdin)['suiSignature'])")
  else
    # Deliberately not a real transaction. stub-accept-all performs the
    # structural checks and moves nothing.
    tx="cGxhY2Vob2xkZXItdHg="
    sig="cGxhY2Vob2xkZXItc2ln"
  fi

  NETWORK="$network" AMOUNT="$amount" ASSET="$asset" PAY_TO="$pay_to" TX="$tx" SIG="$sig" \
  python3 <<'PY'
import base64, json, os

# The client echoes back the requirements it accepted; the server re-checks
# every field, so these must match the challenge exactly.
payload = {
    "x402Version": 2,
    "accepted": {
        "scheme": "exact",
        "network": os.environ["NETWORK"],
        "amount": os.environ["AMOUNT"],
        "asset": os.environ["ASSET"],
        "payTo": os.environ["PAY_TO"],
        "maxTimeoutSeconds": 60,
    },
    "payload": {"signature": os.environ["SIG"], "transaction": os.environ["TX"]},
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
PY
}
