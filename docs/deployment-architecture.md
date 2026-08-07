# Deployment architecture

Where to run the verifier, what state it needs, and what that costs. This is
reasoning rather than a runbook — `deploy/README.md` has the commands.

Read [`how-it-works.md`](how-it-works.md) first; this assumes you know what
`ext_proc` does and why settlement happens on the response.

## The one structural fact

`ext_proc` sends the verifier **headers only**:

```yaml
request_body_mode:  NONE
response_body_mode: NONE
```

No request or response payload ever leaves Envoy's data path. The verifier is a
decision consulted on the side, never a hop. A 4KB response and a 4MB response
cost the gate the same.

Everything below follows from that. The verifier is latency-sensitive and
availability-critical, but it is not bandwidth-sensitive and does not scale with
payload size.

## Where the verifier runs

Envoy consults the verifier twice per request — request headers in, response
headers out. Both are gRPC round trips, so **the distance between Envoy and the
verifier is paid twice on every request**.

| Placement | Round trips cost | Notes |
|---|---|---|
| **Sidecar, same pod** | loopback | Recommended. In a mesh, Envoy is already per-pod |
| Same node, separate pod | ~0.2ms each | Fine |
| Different node, same AZ | ~0.5–1ms each | Noticeable against a fast upstream |
| Cross-AZ | ~1–2ms each | Two hops each way; hard to justify |

In a mesh the data plane *is* Envoy, so a verifier sidecar adds no new hop at
all — `deploy/istio-envoyfilter.yaml` is a working `ext_proc` filter for exactly
this. The single-binary deploy in `deploy/` puts Envoy, the verifier, Redis and
the demo in one network namespace (`network_mode: service:envoy`), which is the
same loopback property achieved with compose instead of a mesh.

A shared cluster-wide verifier deployment is the one shape to avoid. It buys
nothing — the verifier is stateless apart from its store — and it converts every
request into two cross-node round trips.

## Per-service or one shared gate

Per-service works cleanly, because **the policy is already the sharding
boundary**.

Every piece of state the verifier holds is scoped to a policy, and a policy
belongs to one route on one service:

- **Sessions** are minted against the policy that sold them, so a session bought
  on a cheap route cannot unlock an expensive one. A session issued by service A
  is meaningless to service B by construction.
- **Rate limits** are keyed `{policy}|{ip_bucket}` (`ratelimit::key_for`), so a
  free allowance spent on one route is not also spent on another.
- **Replay claims** partition themselves. `check_terms` refuses any payment
  whose `payTo` does not match the policy's configured payee, so a payment built
  for service A cannot verify against service B when they credit different
  wallets. The protocol enforces the split; the store does not have to.

That last one has a caveat worth stating: **if two services share a payee, an
asset and a price, the same signed transaction satisfies both.** Presented to
both concurrently, both verify, both serve, one settles and one does not. The
chain rejects the second execution, so nobody is double-charged — the cost is
one request given away, which
[`settlement-failure.md`](settlement-failure.md) covers and the circuit breaker
bounds. If you want that closed rather than bounded, those services need to
share a replay store, or simply use distinct payees.

## What actually needs shared state

Not everything, and the distinction matters for small deployments.

| State | Shared across replicas? | Why |
|---|---|---|
| Session **validity** | **No** | An HMAC over `payer:expires:session_id`. Any replica verifies it with the secret alone |
| Session **quota** | Yes | Otherwise each replica grants the full quota independently |
| Rate-limit windows | Yes | Otherwise the effective limit is N× the configured one |
| Replay claims | Yes | The window before settlement lands is exactly what they close |

So a service running a **single** verifier replica needs no Redis at all;
`backend: memory` is correct and is the fastest option. Redis becomes necessary
the moment a service runs more than one, which in a sidecar model means the
moment the service runs more than one pod.

`memory` with multiple replicas is a silent correctness bug — the rate limit
becomes N× and sessions become replica-affine. The config comment says
"run exactly one replica" for that reason.

## Redis placement

Redis is **inside the decision**, on the request path. It is not a background
store.

Co-locate it. On the current deployment `redis_url` is `127.0.0.1:6379` and the
verifier's whole decision measures 0.3–0.5ms including that round trip. A
managed Redis in another AZ can cost more than the entire rest of the gate.

Sizing is not the concern. The working set is sessions, replay claims and
rate-limit windows, all TTL'd, all small. Latency is the only thing to optimise
for.

**One Redis per cluster is usually right, not one per service.** Keys are
already namespaced by policy, so a shared instance gives logical isolation
without N deployments to operate. The tradeoff is a shared blast radius, which
both stores mitigate by failing **closed** — `x402_store_errors_total` counts it
and requests are denied rather than waved through.

### Why not etcd

etcd is the wrong shape for this workload:

- It reaches consensus via Raft on every write. Rate limiting writes on *every
  request*.
- It is tuned for low-volume configuration data with watch semantics, not
  per-request counters.
- Its expiry is leases rather than `EXPIRE`, and lease churn at request rate is
  expensive.
- Atomicity here is Lua scripts (`session.rs`, `ratelimit.rs`). etcd has
  transactions but no scripting, so those would have to be rewritten as
  compare-and-swap loops.

etcd *would* fit a problem this does not yet have: distributing policy
configuration to many verifiers, where writes are rare and watches are the point.

## Availability

```yaml
failure_mode_allow: false
```

If the verifier is unreachable, Envoy fails the request rather than passing it
through unpaid. That is the correct default for a payment gate — the alternative
is that a verifier crash silently converts a paid API into a free one — but it
has a consequence worth being explicit about:

**The verifier is in the availability path of every gated request.** A gate that
is down is an API that is down.

This is the strongest argument for the sidecar model. A per-pod verifier shares
the fate of the pod it gates, so its failure domain matches the thing it
protects. A shared verifier deployment becomes a single point of failure for
every service behind it.

`message_timeout: 5s` bounds a single phase. Generous enough for on-chain
verification, but it means a wedged verifier holds a request for five seconds
before failing. Lower it if your upstream SLO is tighter than that.

## Latency

Measured on the deployed demo, where **Envoy, the verifier and Redis share one
network namespace on one VM**. Every internal hop is loopback. Read these as a
floor:

```
x402-decide           0.3 – 0.5 ms   the verifier's own decision, incl. Redis
upstream-service-time   7 – 14 ms    the actual GraphQL call
```

Two honest caveats:

1. `x402-decide` is the verifier's **internal** timer. It does not include the
   Envoy↔verifier transit, which is invisible on loopback and is not on any
   other topology. True gate cost is `2 × transit + decide`.
2. The chain-facing figures below *are* real — they cross the public internet to
   a fullnode.

Latency is bimodal, and the split is the reason sessions exist:

| Path | Cost | Share of live traffic |
|---|---|---|
| Free tier or valid session | decide + 2 transits | 452 of 459 requests |
| Payment verification | ~22ms mean, hits the fullnode | 15 |
| Settlement | ~439ms mean, on the response path | 7 |

Settlement is paid **once per session**, not once per request. One payment
covering a 1000-request session amortises to well under a millisecond each.
Without sessions the gate would add half a second to every call.

Settlement also lands on the response path, after the upstream has already
produced its answer, so it delays delivery of a response that already exists
rather than delaying the work.

### Not measured

Stated plainly because the numbers above invite over-confidence:

- **Gate cost off loopback.** Isolating it needs a route that bypasses
  `ext_proc` to the same upstream, compared under identical load. Not done.
- **Concurrency beyond ~30.** `ext_proc` holds one gRPC stream per in-flight
  request, so 5k concurrent requests means 5k concurrent streams. HTTP/2 caps
  concurrent streams per connection, so the pool has to be sized or requests
  queue invisibly. At the load this has actually seen, the *upstream* returned
  429 before the gate showed strain.
- **Redis slow rather than down.** Failing closed handles unreachable. Degraded
  is the nastier case and is untested.
- **Two-replica Redis-backed operation**, beyond the CI integration tests.

## Streaming

A filter fires once per *stream*, at headers time. A 20-second subscription
delivering 53 messages cost 2 authorization checks; a stream held open for hours
costs one.

Cheap, and also why streaming is effectively unmetered. `grpc-timeout` is
injected so a stream cannot outlive the session that paid for it — bounded by
the session's remaining **lifetime**, not by its quota, since quota is spent per
request and a stream is one request. That limits the exposure without pricing it
properly. Metering streams by time period rather
than per message is the intended fix; per-message metering would put the
verifier in the data path of every chunk, which is exactly what the header-only
processing mode avoids.
