# sui-x402-verifier

An [x402](https://docs.x402.org) payment-gated Envoy `ext_authz` service, written in Rust,
that sells elevated API rate limits for USDC on Sui.

Anonymous clients get a small free tier. When they exhaust it they receive
**HTTP 402 Payment Required** with machine-readable payment terms instead of a
dead-end 429. Paying unlocks a higher-limit session. No accounts, no API keys.

```
                                     ┌─▶ graphql.testnet.sui.io   (HTTP/JSON)
   client ──▶ Envoy :10000 ──────────┤
                    │                └─▶ fullnode.testnet.sui.io  (gRPC/TLS)
                    │
                    └──ext_authz──▶ x402-verifier :50051 ──▶ memory | redis
```

The proxied API is the Sui testnet itself, so the thing being rate limited and
the chain being paid on are the same network.

## Status

| Piece | State |
|---|---|
| Envoy `ext_authz` gate, free/paid tiers | Working, tested end to end |
| x402 v2 challenge / payment / receipt headers | Working |
| HMAC session tokens, quota + TTL | Working |
| Per-route pricing and wallets | Working |
| Redis backend for multi-replica deployments | Working, integration-tested |
| **On-chain verification and settlement** | **Not implemented** — see below |

`verification_mode: stub-accept-all` accepts any well-formed payment **without
touching the chain and without moving funds**. It exists to develop the protocol
plumbing. `sui-grpc` is the real mode; it currently rejects every payment rather
than silently falling back to the stub. Nothing here has custody of anything yet.

## Quick start

Needs Rust, and Envoy (the script fetches one via [func-e](https://func-e.io) if
you have neither `envoy` nor `func-e` installed).

```bash
scripts/run-local.sh          # builds, starts the verifier + Envoy
scripts/e2e-test.sh           # in another shell: 13 assertions over the full flow
```

By hand — the first 5 requests succeed, the 6th gets a challenge:

```bash
curl -i -X POST localhost:10000/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ chainIdentifier }"}'
```

```
HTTP/1.1 402 Payment Required
payment-required: eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJmcmVlIHRpZXIg...
content-type: application/json
```

Base64-decode that header to get the terms: `payTo`, `maxAmountRequired`,
`asset`, `network`, `maxTimeoutSeconds`.

## Browser demo

`demo/index.html` is a dependency-free page that drives the whole flow: call the
API until the free tier is spent, watch the decoded challenge appear, pay, and
watch calls resume on a session.

```bash
scripts/run-local.sh                       # terminal 1
python3 -m http.server 8080 -d demo        # terminal 2 → open localhost:8080
```

x402 is browser-native — it is ordinary HTTP — but two things must be right or a
web page cannot use it at all:

- **`Access-Control-Expose-Headers`.** Browsers hide response headers from JS by
  default, so without this the page sees the `402` status but *not* the terms,
  the session token, or the receipt. `envoy.yaml` exposes all three.
- **The CORS filter must run before `ext_authz`.** Otherwise the preflight
  `OPTIONS` is itself metered and answered with `402`, and the browser never
  sends the real request.

### grpc-web

Browsers cannot speak native gRPC — `fetch`/XHR expose no control over HTTP/2
frames, and HTTP/2 trailers are unreadable from JS. grpc-web solves this by
carrying trailers in the response body, and Envoy's `grpc_web` filter translates
it so the upstream fullnode needs no changes. Verified working from a browser
origin, both directions:

```
allowed:  HTTP 200, content-type: application/grpc-web+proto → real Sui data
denied:   HTTP 200, grpc-status: 8, grpc-message: free tier rate limit exceeded…
          payment-required: <base64 challenge>
```

`grpc-status` and `grpc-message` must be in `expose_headers` or a grpc-web client
cannot read the denial, and `x-grpc-web` / `grpc-timeout` must be in
`allow_headers` or the preflight fails. Both are set.

### Signing in the browser

A browser cannot sign a Sui transaction on its own — that needs a wallet
extension (Slush, Suiet, …) through the Wallet Standard, normally via
`@mysten/dapp-kit`, or zkLogin.

The important detail: use **`signTransaction`, not
`signAndExecuteTransaction`**. x402 wants a signed-but-unsubmitted
authorization, because the *facilitator* is what submits it. `useSignTransaction`
returns `{ bytes, signature }`, which map straight onto `transactionBytes` and
`signatures[0]` in the payment payload — so wiring a real wallet into
`demo/index.html` means replacing two placeholder strings.

None of this is a proxy concern: the verifier reads a header and does not care
how the signature was produced. In `stub-accept-all` mode no wallet is needed.

## Configuration

See `config.example.yaml`. Two values should never be committed and can be
supplied by environment instead:

```bash
export X402_SESSION_HMAC_SECRET=$(openssl rand -hex 32)
export X402_PAY_TO=0x<your 64-hex-char Sui address>
```

The example config ships the **zero address** as `pay_to`, and the service
**refuses to start** with it — settling there would burn funds, so an
unconfigured deployment fails loudly instead of quietly misrouting payments.

### Pricing multiple routes

Two mechanisms. Prefer the first.

**Named policies (recommended).** Envoy already knows which route matched, so it
just names a policy on the ext_authz callout. This config never repeats a path
prefix, so the two files cannot drift on routing:

```yaml
# envoy.yaml — on the route
typed_per_filter_config:
  envoy.filters.http.ext_authz:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
    check_settings:
      context_extensions: { x402_policy: grpc }
```

```yaml
# config.yaml — what that policy costs
policies:
  grpc:    { max_amount_required: "5000", pay_to: "0x…", description: "gRPC calls" }
  graphql: { max_amount_required: "100" }
```

**Path prefixes (fallback).** For gateways that cannot attach per-route metadata
to an ext_authz callout (Kong, APISIX). This *does* duplicate path knowledge:

```yaml
routes:
  - path_prefix: "/sui.rpc.v2."
    max_amount_required: "5000"
```

Longest prefix wins, so file order is irrelevant. A policy outranks a prefix
rule; an unknown policy name logs a warning and falls back rather than failing
the request.

### State backend

```yaml
store:
  backend: memory                        # or: redis
  # redis_url: "redis://127.0.0.1:6379"
```

`memory` is per-process. **Run exactly one replica on it** — with N replicas the
effective rate limit becomes N× the configured value and sessions are
replica-affine. `redis` shares state properly; both the quota decrement and the
rate-limit window are Lua scripts so they are atomic across replicas.

Both backends fail **closed**: if Redis is unreachable, requests are denied
rather than admitted unmetered.

## How rate limits reach Envoy

Envoy does not know about tiers — the verifier tells it on every request, by
injecting `x-x402-tier: free|paid` and `x-x402-payer: 0x…` into the request, plus
the same values as dynamic metadata.

Two constraints make or break this:

- **`ext_authz` must precede `ratelimit`** in `http_filters`, or descriptors get
  built from headers that do not exist yet.
- **Those headers must be set with `OverwriteIfExistsOrAdd`, never append.**
  Otherwise a client sends its own `x-x402-tier: paid` and self-promotes. That is
  the entire security boundary, and it is pinned by a test.

The verifier currently enforces the free tier in-process. To scale out, demote it
to a classifier and let `envoyproxy/ratelimit` + Redis own the counters — the
headers and metadata it already emits are exactly what that needs, so it is a
config change rather than a rewrite. `envoy.yaml` has the descriptor block
commented out and ready.

## Notes from building this

Things that were not true of the original design and cost real debugging time:

- **Sui fullnodes have removed JSON-RPC.** `suix_getBalance`,
  `dryRunTransactionBlock` and `executeTransactionBlock` all return
  `Method not found`. gRPC (`sui.rpc.v2.*`) is the only supported interface, and
  it is what the settlement path must target:

  | Step | Call |
  |---|---|
  | recover/validate signer | `SignatureVerificationService.VerifySignature` |
  | check the payer can afford it | `StateService.GetBalance` |
  | confirm the tx would land | `TransactionExecutionService.SimulateTransaction` |
  | settle | `TransactionExecutionService.ExecuteTransaction` |

- **gRPC needs its own error framing.** gRPC clients collapse any non-200 HTTP
  status into an opaque transport error, so a raw `402` arrived as
  `code = Unknown` with the terms buried in a string. Denials for gRPC requests
  are therefore sent as a trailers-only response — HTTP 200 carrying
  `grpc-status: 8` (RESOURCE_EXHAUSTED) — which clients surface properly as
  `code = ResourceExhausted`, with the challenge still readable as metadata.

- **Streaming RPCs are effectively unmetered.** `ext_authz` fires once per
  *stream*, at headers time, never per message. A 20-second
  `SubscribeCheckpoints` stream delivering 53 messages consumed 2 authz checks
  total; a stream held open for hours costs 1. Paid streaming needs duration or
  message caps, not per-request counting. Not yet implemented.

- **gRPC reflection consumes free-tier quota.** `grpcurl` resolves method
  descriptors via `grpc.reflection.v1.*` before the real call, and that callout is
  gated like any other request. Exempting it is a policy decision, currently not
  taken.

- **Envoy prefers AAAA by default.** On a DNS64/NAT64 network that yields a
  synthesized `64:ff9b::/96` address which is unroutable without a NAT64 gateway,
  surfacing as `503 upstream connect timeout` while IPv4 to the same host works
  fine. Both upstream clusters pin `dns_lookup_family: V4_ONLY`.

- Testnet USDC is
  `0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC`
  — 6 decimals, so `"1000"` is 0.001 USDC. Faucet:
  [faucet.circle.com](https://faucet.circle.com), chain "Sui Testnet". Testnet SUI
  for gas: `sui client faucet`. **Neither is needed in stub mode.**

## Testing

```bash
cargo test                                   # 66 unit tests
redis-server --port 6399 --daemonize yes
X402_TEST_REDIS_URL=redis://127.0.0.1:6399 cargo test   # + 12 Redis integration tests
scripts/e2e-test.sh                          # 13 end-to-end assertions
```

Redis tests no-op when `X402_TEST_REDIS_URL` is unset, so the suite passes on a
machine without Redis.

## Security notes

- Session tokens are `payer:expires:session_id:hmac`. The MAC is verified in
  constant time before any field is trusted; a tampered token is rejected without
  a store lookup.
- Quota uses compare-exchange (memory) or Lua (Redis). A plain decrement would
  wrap `0u64` to `u64::MAX` and grant effectively unlimited requests.
- The client's `payment-signature` and `x-payment-session` headers are stripped
  before the request reaches the backend.
- Requests with no resolvable source address are denied — an unmeterable free
  tier is an unmetered one.
- **Not yet enforced:** that a client's signed transaction actually pays
  `pay_to`. That check belongs in the `sui-grpc` verify path; without it a client
  could sign a payment to themselves. This is why `sui-grpc` rejects everything
  rather than half-working.

## License

Apache-2.0
