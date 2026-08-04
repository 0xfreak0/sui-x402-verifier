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
| On-chain verification (`sui-grpc`) | **Working**, validated against live testnet |
| On-chain settlement | Implemented; broadcast path not yet exercised on testnet |

Two verification modes:

- `stub-accept-all` — accepts any well-formed payment **without touching the
  chain and without moving funds**. For protocol work. Receipts say
  `stub-not-settled-on-chain` so they can never be mistaken for evidence.
- `sui-grpc` — runs all four `scheme_exact_sui.md` verification steps against a
  fullnode. The payer is **recovered from the signature**, never taken from a
  client-supplied field.

Validated against live Sui testnet with a real wallet-signed transfer of
0.00001 USDC:

```
honest payment                     isValid: true,  payer: 0x83cb…
tampered signature (byte flipped)  isValid: false, invalid_payload
chain we do not serve              isValid: false, invalid_network
server wants more than tx pays     isValid: false, invalid_payment_requirements
server wants a different payee     isValid: false, invalid_payment_requirements
```

Reproduce with `scripts/pay-with-sui-cli.sh`, which builds and signs a real
transfer using your `sui` CLI wallet. It calls `/verify` (simulation only, no
funds move) unless you pass `--settle`.

## Quick start

Needs Rust, and Envoy (the script fetches one via [func-e](https://func-e.io) if
you have neither `envoy` nor `func-e` installed).

```bash
scripts/run-local.sh          # builds, starts the verifier + Envoy
scripts/e2e-test.sh           # in another shell: 14 assertions over the full flow
```

Against a gateway in `sui-grpc` mode, run the same suite with a **real**
wallet-signed payment. This settles on chain and moves testnet USDC:

```bash
scripts/e2e-test.sh --real
```

Verified doing exactly that — a 0.00001 USDC payment through Envoy, settled
after the upstream succeeded:

```
✓ payment accepted, HTTP 200 while the free tier is still exhausted
✓ session token issued
✓ PAYMENT-RESPONSE receipt: {"success":true,"transaction":"5WWWLaQNw6Xd…"}
✓ session reused without re-paying
Result: 14 passed, 0 failed
```

On chain: `effects.status.success = true`, checkpoint `368081861`, recipient
credited exactly 10 base units.

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

**`use_remote_address: true` is security critical.** With Envoy's default
(`false`) it treats itself as an internal proxy and derives the downstream
remote address **from the `x-forwarded-for` header** — which is the address the
free tier is metered on. A client could then send `X-Forwarded-For: <random>`
on every request and get an unlimited free tier. Setting it to `true` makes
Envoy use the real TCP peer, which a client cannot forge. If you put a load
balancer in front, keep it `true` and set `xff_num_trusted_hops` to the number
of proxies you actually control.

Two further constraints make or break this:

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

## Conformance

Wire format follows x402 **v2**, vendored at `docs/spec/upstream/` (coinbase/x402
@ `dd927a26`). The spec's own JSON examples are extracted into `tests/fixtures/`
and round-tripped through the types, so a shape that drifts fails CI rather than
failing silently against a real client.

### Settlement ordering: `ext_proc` (default) vs `ext_authz`

`scheme_exact_sui.md` steps 6-8 sequence the flow as **verify → resource server
does the work → settle**, so a client is charged only once the resource has
actually been produced. Which filter you use decides whether that is achievable:

| Filter | Sequencing | Charged for a failed request? |
|---|---|---|
| **`ext_proc`** (default) | verify → upstream → settle on 2xx | no |
| `ext_authz` | verify+settle → upstream | **yes** |

`ext_authz` is a *pre-upstream* filter: it runs on the request path, cannot see
the response, and must answer allow/deny before Envoy proxies anything. There is
nowhere later to settle from.

`ext_proc` can, because Envoy opens **one bidirectional gRPC stream per HTTP
request** and sends request headers then response headers on that same stream.
The verified-but-unsettled payment is held as ordinary stream-local state — no
shared map, no correlation id, no eviction policy — and settled only after a 2xx.

Both are implemented and served on the same port; `envoy.yaml` selects between
them. Do not enable both, or each will independently charge for the same request.

Verified end to end: a payment on a path where the upstream 404s produces **no
`PAYMENT-RESPONSE` and no session**, while the same payment on a working path
settles normally. An unsettled claim is also *released* from the replay cache, so
the client can retry with the same signed transaction rather than signing a new
one for a failure that was not theirs.

**Residual risk, stated plainly:** deferring settlement moves the failure rather
than removing it. If the upstream succeeds but settlement then fails, the
resource has already been delivered unpaid. That is the opposite exposure to
`ext_authz`'s, and the better one to carry — it costs the operator a request
instead of charging a user for something they never received.

### Facilitator interface

`POST /verify`, `POST /settle`, `GET /supported` (§7) are implemented but
**disabled unless `facilitator_api_listen_addr` is set**. Envoy never calls
them: it uses the ext_authz gRPC service, where verification and settlement
happen together inside one `Check()`. §7 exists so *other* x402 resource servers
can delegate Sui work here.

Note this makes the binary **self-facilitating** — the same process is both the
resource server and its own facilitator. That is a legitimate x402 deployment,
but there is no trust boundary between the two halves. The endpoints are
unauthenticated; bind them to loopback or a private interface.

### Sessions are a declared extension

The paid-session token is advertised through §5.1.2's `extensions` map rather
than as an undocumented header: `PaymentRequired.extensions` carries an `info`
and a JSON `schema`, a settled payment returns the token in the receipt's
`extensions`, and a client may echo it back the same way. The raw
`x-payment-session` header still works as a deprecated alias.

### What still has custody of nothing

`/supported` reports an empty `signers` map, and the service holds no keys. It
never signs anything: the client signs, and settlement re-broadcasts what the
client already signed. Sponsorship — which *would* require a funded hot wallet —
is advertised only, never performed.

### Out of scope

- The Bazaar / discovery endpoints (§8).
- The `a2a` and `mcp` transports — only `http` is implemented.
- The interactive gas-station sponsorship protocol. Sponsorship is *advertised*
  via `extra.gasStation` when configured, but the protocol itself is not
  implemented, and this facilitator holds no signing keys (`/supported` reports
  an empty `signers` map, which is how you can check that).

Known spec gaps found while implementing: `docs/spec-gaps.md`.

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
