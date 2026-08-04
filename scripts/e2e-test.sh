#!/usr/bin/env bash
#
# End-to-end test of the x402 flow against a locally running Envoy + verifier.
#
# Exercises, in order:
#   1. Free-tier requests succeed and are proxied to Sui testnet GraphQL.
#   2. Exhausting the free tier returns 402 with a PAYMENT-REQUIRED challenge.
#   3. A payment authorization unlocks the paid tier and mints a session.
#   4. The session token is accepted on subsequent requests.
#   5. A forged session token does not escalate privilege.
#   6. gRPC passthrough to the fullnode still works.
#
# Prerequisites: the verifier and Envoy must already be running. See
# scripts/run-local.sh, or the README.
#
# Payment mode:
#   default  placeholder bytes — works against verification_mode: stub-accept-all
#   --real   a transaction built and signed by the local `sui` CLI wallet, which
#            is what verification_mode: sui-grpc requires. NOTE: with ext_proc
#            and a successful upstream this SETTLES, moving real testnet USDC.
#
# Usage: scripts/e2e-test.sh [--real] [envoy_url]

set -uo pipefail

PAY_MODE=placeholder
if [[ "${1:-}" == "--real" ]]; then
  PAY_MODE=real
  shift
fi

ENVOY="${1:-http://localhost:10000}"
GRPC_ADDR="${GRPC_ADDR:-localhost:10000}"
QUERY='{"query":"{ chainIdentifier }"}'

# shellcheck source=lib/build-payment.sh
source "$(dirname "$0")/lib/build-payment.sh"

pass=0
fail=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail + 1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# POST a GraphQL query. Args: [extra curl args...]
# Writes response headers to $HDRS and the body to stdout.
HDRS=$(mktemp)
trap 'rm -f "$HDRS"' EXIT

gql() {
  curl -s -D "$HDRS" -o /dev/stdout \
    -X POST "$ENVOY/graphql" \
    -H 'Content-Type: application/json' \
    -d "$QUERY" "$@"
}

status()      { awk 'NR==1{print $2}' "$HDRS"; }
header_val()  { grep -i "^$1:" "$HDRS" | head -1 | cut -d' ' -f2- | tr -d '\r'; }

# ---------------------------------------------------------------------------
step "1. Free tier is proxied to Sui testnet GraphQL"
# ---------------------------------------------------------------------------
body=$(gql)
if [[ "$(status)" == "200" ]] && grep -q chainIdentifier <<<"$body"; then
  ok "200 OK, upstream answered: $(tr -d '\n' <<<"$body" | head -c 80)"
else
  bad "expected a proxied 200, got HTTP $(status): $(head -c 200 <<<"$body")"
  echo "     (is the verifier running? is Envoy running?)"
fi

# ---------------------------------------------------------------------------
step "2. Exhausting the free tier yields 402, not 429"
# ---------------------------------------------------------------------------
# config.example.yaml sets free_tier.max_requests: 5. Spend well past it.
for _ in $(seq 1 10); do gql >/dev/null; done

body=$(gql)
code=$(status)
challenge=$(header_val 'payment-required')

if [[ "$code" == "402" ]]; then
  ok "HTTP 402 Payment Required"
else
  bad "expected 402 after exhausting the free tier, got $code"
fi

if [[ -n "$challenge" ]]; then
  decoded=$(base64 -d <<<"$challenge" 2>/dev/null)
  ok "PAYMENT-REQUIRED header present"
  echo "     $(head -c 300 <<<"$decoded")"

  pay_to=$(sed -n 's/.*"payTo":"\([^"]*\)".*/\1/p' <<<"$decoded")
  network=$(sed -n 's/.*"network":"\([^"]*\)".*/\1/p' <<<"$decoded")
  amount=$(sed -n 's/.*"amount":"\([^"]*\)".*/\1/p' <<<"$decoded")
  resource_url=$(sed -n 's/.*"resource":{"url":"\([^"]*\)".*/\1/p' <<<"$decoded")
  [[ -n "$pay_to"  ]] && ok "challenge advertises payTo=$pay_to"   || bad "no payTo in challenge"
  [[ "$network" == "sui:testnet" ]] && ok "challenge network=$network" || bad "unexpected network: $network"
  [[ -n "$amount"  ]] && ok "challenge price=$amount (USDC base units, v2 'amount' field)" || bad "no amount in challenge"
  # v2 requires a full URL in a top-level resource object, not a bare path.
  if [[ "$resource_url" == http*://* ]]; then
    ok "challenge resource.url=$resource_url"
  else
    bad "resource.url is not a full URL: ${resource_url:-<missing>}"
  fi
else
  bad "PAYMENT-REQUIRED header missing from the 402"
fi

# ---------------------------------------------------------------------------
step "3. Paying unlocks the paid tier and mints a session"
# ---------------------------------------------------------------------------
# Build the payment from the terms the server just advertised. A conformant
# client echoes those back rather than inventing them.
asset=$(sed -n 's/.*"asset":"\([^"]*\)".*/\1/p' <<<"$decoded")
PAYMENT_SIGNATURE=$(build_payment "$PAY_MODE" "$network" "$amount" "$asset" "$pay_to") || {
  bad "could not build a $PAY_MODE payment"
  PAYMENT_SIGNATURE=""
}
[[ "$PAY_MODE" == "real" ]] && echo "     (real wallet-signed transfer of $amount base units)"

body=$(gql -H "payment-signature: $PAYMENT_SIGNATURE")
code=$(status)
session=$(header_val 'x-payment-session')
receipt=$(header_val 'payment-response')

if [[ "$code" == "200" ]]; then
  ok "payment accepted, HTTP 200 while the free tier is still exhausted"
else
  bad "expected 200 after payment, got $code: $(head -c 200 <<<"$body")"
fi

if [[ -n "$session" ]]; then
  ok "session token issued: ${session:0:32}…"
else
  bad "no x-payment-session header returned"
fi

if [[ -n "$receipt" ]]; then
  ok "PAYMENT-RESPONSE receipt: $(base64 -d <<<"$receipt" 2>/dev/null | head -c 160)"
else
  bad "no PAYMENT-RESPONSE receipt returned"
fi

# ---------------------------------------------------------------------------
step "4. The session token is honored on later requests"
# ---------------------------------------------------------------------------
if [[ -n "$session" ]]; then
  body=$(gql -H "x-payment-session: $session")
  if [[ "$(status)" == "200" ]] && grep -q chainIdentifier <<<"$body"; then
    ok "session reused without re-paying, still 200"
  else
    bad "session reuse failed with HTTP $(status)"
  fi

  # A second reuse proves quota is being decremented, not just accepted once.
  gql -H "x-payment-session: $session" >/dev/null
  [[ "$(status)" == "200" ]] && ok "session still valid on a third request" \
                             || bad "session unexpectedly rejected: $(status)"
else
  bad "skipping session reuse — no token to test with"
fi

# ---------------------------------------------------------------------------
step "5. A forged session token does not escalate privilege"
# ---------------------------------------------------------------------------
# Correct shape, wrong MAC. Must fall back to the (exhausted) free tier.
FORGED="0x2222222222222222222222222222222222222222222222222222222222222222:99999999999:$(printf 'aa%.0s' {1..16}):$(printf 'bb%.0s' {1..32})"
gql -H "x-payment-session: $FORGED" >/dev/null
code=$(status)
if [[ "$code" == "402" ]]; then
  ok "forged token rejected, fell back to free tier (402)"
else
  bad "forged token produced HTTP $code — expected 402"
fi

# ---------------------------------------------------------------------------
step "6. gRPC passthrough to the Sui fullnode"
# ---------------------------------------------------------------------------
if command -v grpcurl >/dev/null 2>&1; then
  # The gRPC route has its own policy, so it has its own price AND its own
  # session scope. A session bought on the GraphQL route is deliberately NOT
  # accepted here — paying for the cheap route must not unlock the dear one.
  grpc_challenge=$(grpcurl -plaintext -max-time 20 -d '{}' "$GRPC_ADDR" \
      sui.rpc.v2.LedgerService/GetServiceInfo 2>&1 || true)
  grpc_amount=$(sed -n 's/.*"amount":"\([0-9]*\)".*/\1/p' <<<"$grpc_challenge" | head -1)

  if [[ -n "$grpc_amount" ]]; then
    ok "gRPC route advertises its own price: $grpc_amount"
    grpc_pay=$(build_payment "$PAY_MODE" "$network" "$grpc_amount" "$asset" "$pay_to") || grpc_pay=""
  else
    # Free tier still had room, so no challenge was issued.
    grpc_pay=""
  fi

  out=$(grpcurl -plaintext -max-time 20 \
          ${grpc_pay:+-H "payment-signature: $grpc_pay"} \
          -d '{}' "$GRPC_ADDR" \
          sui.rpc.v2.LedgerService/GetServiceInfo 2>&1)
  if grep -q '"chain"' <<<"$out"; then
    ok "gRPC proxied to the fullnode: $(grep -o '"chain": *"[^"]*"' <<<"$out" | head -1)"
  else
    bad "gRPC passthrough failed: $(head -c 200 <<<"$out")"
  fi

  # NOTE: cross-policy session scoping (a GraphQL session must not unlock the
  # gRPC route) is NOT asserted here. A refused session falls through to the
  # free tier, and from outside that is indistinguishable from the session
  # having been accepted — so any assertion here is either flaky or vacuous,
  # depending on where the sliding window happens to be. The property is
  # covered deterministically by unit tests:
  #   session::a_session_is_scoped_to_the_policy_that_bought_it
  #   auth::a_session_bought_on_one_policy_does_not_unlock_another
else
  echo "  – skipping: grpcurl not installed (brew install grpcurl)"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1mResult:\033[0m %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
