# Configuring Envoy and the verifier

Two config files that have to agree without duplicating each other, and a set of
settings where a plausible-looking mistake quietly gives away the paid tier.

Every section ends with a way to check the setting is actually doing what you
think. Most of the failures here are silent — the gateway serves traffic, the
tests pass, and the free tier is forgeable.

---

## Who owns what

The split matters because getting it wrong means maintaining the same fact in
two places and watching them drift.

| | Owns |
|---|---|
| `envoy.yaml` | which paths exist, where they go, which **policy name** each route uses |
| the verifier's config | what each **policy name** costs, where it pays, what it gives away |

Envoy never learns a price. The verifier never learns a path. They meet at a
string:

```yaml
# envoy.yaml — this route is sold under the name "graphql"
- match: { prefix: "/graphql" }
  metadata:
    filter_metadata:
      envoy.filters.http.ext_proc:
        x402_policy: graphql
```

```yaml
# config.yaml — what "graphql" costs
policies:
  graphql:
    amount: "10000"
    free_tier: { max_requests: 5, window_secs: 60 }
    paid_tier: { quota: 1000, duration_secs: 3600 }
```

A policy name in Envoy that the verifier does not define falls back to the
default terms and logs a warning. It does not fail the request, because a
routing change should not take payments down.

**Check it:**

```bash
# The resolved table, without spending a free-tier request to discover it.
curl -s localhost:50052/policies | jq '.[] | {name, amount, payTo, freeRequests}'

# And that a route actually resolves to the policy you think:
grep -A3 x402_policy envoy.yaml
```

If a route's challenge shows the default price rather than the policy's, the
name is misspelled on one side. Watch for `falling back to default payment
terms` in the verifier log.

---

## The settings that are security-critical

### `use_remote_address` and `xff_num_trusted_hops`

The free tier is metered per source address. If Envoy resolves the wrong
address, either everyone shares one bucket (the demo looks broken) or every
client can mint themselves a fresh allowance by varying a header (the free tier
is unlimited).

```yaml
use_remote_address: true
xff_num_trusted_hops: 1   # exactly the number of proxies YOU control
```

`0` means use the TCP peer, which is right when Envoy is the edge. `1` means
trust one hop of `X-Forwarded-For`, which is right when exactly one proxy you
control sits in front and **replaces** the header. Caddy's
`header_up X-Forwarded-For {remote_host}` replaces it; a proxy that appends
instead needs a different number.

Set it higher than the number of proxies you actually control and clients can
inject their own address. This is the single easiest way to give away the free
tier.

**Check it:**

```bash
# Spoofing XFF must NOT reset your allowance.
for i in $(seq 8); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST https://HOST/graphql \
    -H 'content-type: application/json' \
    -H "x-forwarded-for: 10.0.0.$i" \
    -d '{"query":"{ chainIdentifier }"}'
done; echo
# Expect the allowance to run out anyway: 200 ... 200 402 402
# All 200s means the header is being trusted and the free tier is forgeable.
```

### `failure_mode_allow`

```yaml
failure_mode_allow: false
```

If the verifier is unreachable, deny. `true` turns an outage into an open proxy,
which is the worst possible failure for a paid gateway and the default people
reach for while debugging.

**Check it:** stop the verifier and issue a request. You want a 5xx, not a 200.

### Filter order

```yaml
http_filters:
  - grpc_web      # before cors, so preflight sees the translated request
  - cors          # BEFORE ext_proc
  - ext_proc      # BEFORE router
  - router
```

`cors` must come first because the CORS filter answers preflight `OPTIONS`
itself and short-circuits the chain. Behind `ext_proc`, every preflight would be
metered and 402'd, and the browser would never send the real request.

`ext_proc` must precede `router` so the headers it injects exist by the time the
route is chosen and any downstream filter reads them.

**Check it:** a browser request from another origin should work. A preflight
that returns 402 means the order is wrong.

### What the verifier asserts, and why it overwrites

The verifier sets `x-x402-tier` and `x-x402-payer` on the upstream request with
`OverwriteIfExistsOrAdd`. Appending would leave a client's own
`x-x402-tier: paid` in place alongside the real one, which is self-promotion into
the paid tier.

**Check it:**

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://HOST/graphql \
  -H 'content-type: application/json' \
  -H 'x-x402-tier: paid' -H 'x-x402-payer: 0xdeadbeef' \
  -d '{"query":"{ chainIdentifier }"}'
# Expect 402 once the free tier is spent. A 200 means the client's header won.
```

The demo page's **Declined** panel runs this and five other bypasses against a
live gateway.

### Reflection and health are not gated

```yaml
- match: { safe_regex: { regex: "^/(grpc\\.reflection|grpc\\.health)\\..*" } }
  typed_per_filter_config:
    envoy.filters.http.ext_proc:
      "@type": .../ExtProcPerRoute
      disabled: true
```

gRPC clients resolve method descriptors via reflection before issuing the real
call, and they attach their headers to that call too. Gate it and the reflection
request consumes the payment, then the real call is refused as a replay. Correct
behaviour, useless client.

---

## Bind addresses

```yaml
listen_addr: "127.0.0.1:50051"              # ext_proc, Envoy dials this
metrics_listen_addr: "127.0.0.1:9090"       # unauthenticated
facilitator_api_listen_addr: "127.0.0.1:50052"  # unauthenticated, /settle moves money
```

None of these may face the internet. `/settle` broadcasts a signed transaction on
the call, and `/policies` lists every receiving wallet.

Under `docker compose` the verifier shares Envoy's network namespace, so these
ports are reachable only inside the stack and are not published to the host at
all. If you run it differently, the firewall is the only thing left.

**Check it, from off the box:**

```bash
for p in 9090 10000 50051 50052 8402; do
  nc -z -w2 YOUR_PUBLIC_IP $p && echo "$p REACHABLE — fix this" || echo "$p closed"
done
```

---

## Pricing

### Stay above the gasless floor

Payments of at least **0.01 USDC** (`amount: "10000"` at 6 decimals) take Sui's
gasless path: the payer needs no SUI, no coin object is pinned, and settlement
costs nothing. Below that the transfer will not execute at all and the payment
falls back to coin objects and gas.

The verifier warns at startup for any policy priced below the floor. It is a
warning rather than an error, because sub-cent pricing is legitimate if you are
content for payers to hold SUI.

Sell a session rather than a request. One payment at the floor covering 1000
requests works out to $0.00001 each.

**Check it:** look for `price is below the gasless stablecoin minimum` at boot,
then confirm a real settlement cost nothing:

```bash
curl -s "https://fullnode.testnet.sui.io/..." # or:
sui client tx-block <DIGEST> | grep -A4 'Gas Cost Summary'
# computation 0, storage 0 means the gasless path was used
```

### Free tier and session size

```yaml
free_tier:  { max_requests: 5, window_secs: 60 }
paid_tier:  { quota: 1000, duration_secs: 3600 }
```

Both limits apply to a session and the first to run out wins. A session sold by
request count is one with a large `duration_secs`; a session sold by duration is
one with a large `quota`.

Keep `max_requests` small enough that a person can reach the 402 by hand. Five is
enough to feel it; fifty is not.

---

## Secrets

```bash
export X402_SESSION_HMAC_SECRET=$(openssl rand -hex 32)   # generate a FRESH one
export X402_PAY_TO=0x...                                  # default payee
export X402_PAY_TO_GRPC=0x...                             # per-policy payee
```

Committed configs carry the zero address and the published placeholder secret,
and the service **refuses to boot on either**. A missing variable fails loudly
instead of settling somewhere wrong or signing sessions with a key printed in a
public repository.

**Check it:** start with the shipped config and no environment. It should refuse,
and the error should tell you what to run.

---

## A verification pass that actually proves something

Run this against a fresh deployment. Each step fails visibly if the setting
above it is wrong.

```bash
HOST=https://your.host

# 1. The free tier meters and then challenges.
for i in $(seq 8); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST $HOST/graphql \
    -H 'content-type: application/json' -d '{"query":"{ chainIdentifier }"}'
done; echo          # want: 200 x N then 402

# 2. The challenge names a resource the client can actually reach.
curl -sD- -o /dev/null -X POST $HOST/graphql \
  -H 'content-type: application/json' -d '{"query":"{ chainIdentifier }"}' \
  | grep -i payment-required | cut -d' ' -f2 | base64 -d | jq '.resource.url'
# An internal address here means x-forwarded-host is not reaching the verifier.

# 3. A real client can pay and be served.
cargo run --bin x402-pay -- $HOST/graphql -X POST \
  -H 'content-type: application/json' -d '{"query":"{ chainIdentifier }"}'

# 4. A failing upstream is NOT charged.
curl -s -X POST $HOST/send -H 'content-type: application/json' \
  -d '{"target":"fail"}' | jq '{status, paid, settled, transaction}'
# want: status 503, paid true, settled false, transaction ""

# 5. Nothing internal is exposed. (see the nc loop above)
```

Step 4 is the one worth doing by hand. It is the property the whole `ext_proc`
design exists to provide, and the only way to be sure of it is to watch a
payment get verified and then not settle.
