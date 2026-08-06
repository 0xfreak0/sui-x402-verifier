# How it works

Start here. The conformance audit and the configuration guide assume you already
have this picture.

## The idea

Envoy already sits in front of your services. It has a hook that lets an external
process approve or reject each request. This is a process that answers that hook
by checking whether the caller paid.

Everything else is detail.

## Three processes

| | Does | Holds keys |
|---|---|---|
| **Envoy** | routes traffic, calls the verifier once per request | no |
| **x402-verifier** | decides free / paid / refused, verifies and settles payments | **no** |
| **x402-demo** | serves the demo page and pays on a visitor's behalf | **yes** — hot wallet, demo only |

The verifier holding no keys is load-bearing. It **relays** a transaction the
client already signed, and broadcasting a signed transaction requires no private
key. That is what lets the gateway charge you without being able to steal from
you: the most a compromised verifier could do is broadcast a payment you already
authorised, to the payee you already agreed to, for the amount you already
signed. `GET /supported` advertises `"signers": {}`, and that has to stay true.

`x402-demo` is the exception and it is scaffolding. It exists so a visitor can
try the flow without installing a wallet, and it is why the spend controls on it
are not optional.

## A request, end to end

```
1.  client sends POST /graphql
2.  Envoy pauses it and ships the request headers to the verifier over gRPC
3.  the verifier asks, in order:
      a valid session token?        -> PAID, spend one from the quota
      a payment-signature header?   -> verify it against the chain
      neither?                      -> free tier, is there allowance left?
4a. allowed -> Envoy proxies to graphql.testnet.sui.io
4b. refused -> 402 carrying machine-readable terms: price, payee, asset, network
5.  the upstream responds, and Envoy pauses AGAIN to show the verifier the
    response headers
6.  2xx? only now does the verifier broadcast the payment
7.  the client gets the response, a receipt, and a session token
```

**Step 5 is the entire reason this uses `ext_proc`.** `ext_authz` is a
request-path filter: it answers allow/deny and never sees the response, so
settling there charges a client whose request then fails. `ext_proc` opens one
bidirectional gRPC stream per request, so the verifier can hold a
verified-but-unbroadcast payment as ordinary stream-local state and settle on the
way out, only on success.

The scheme sequences this as verify → do the work → settle, so a client is only
charged once the resource exists. `ext_authz` cannot express that ordering at
all. It is kept as a fallback and settles early, which is a documented deviation
rather than an accident.

The `/boom` target on the demo exists to make this visible: it always returns
503, the payment is verified, and nothing is charged.

## What each config owns

Two files have to agree without duplicating each other, so they meet at a string.

| | Owns |
|---|---|
| `envoy.yaml` | which paths exist, where they route, and a policy **name** per route |
| the verifier's config | what each **name** costs, where it pays, what it gives away |

Envoy never learns a price. The verifier never learns a path. Adding a route
means touching the route table in one file and a price in the other, and neither
repeats the other's information.

```yaml
# envoy.yaml — this route is sold under the name "graphql"
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

A name Envoy sends that the verifier does not define falls back to the default
terms and logs a warning. A routing change should not take payments down.

## Sessions

Settlement takes around 750ms, and below 0.01 USDC it leaves the gasless path —
the payment still works, but it pins a coin object and the payer needs SUI for
gas. Doing that once per request is unusable, so one payment mints a
**session**: an HMAC-signed token carrying a random id, good for a quota and a
duration, whichever runs out first. One payment at the floor covering 1000
requests is $0.00001 each, without dropping off the gasless path.

A session is prepaid credits. The thing that makes it worth having is that it is
prepaid credits requiring **no account** — no signup, no card, no human — which
is the case an autonomous client cannot otherwise satisfy.

Sessions are scoped to the policy that minted them, so one bought on a cheap
route cannot unlock an expensive one. They are keyed on a random id rather than
on IP or connection, so a client that changes networks keeps what it bought.

## Two payment paths

| | Gasless (default) | Coin object (fallback) |
|---|---|---|
| When | `amount` ≥ 0.01 USDC | below that |
| Funds from | the sender's address balance | a selected `Coin` object |
| Gas | **zero**, and the payer needs no SUI | payer pays, ~0.0023 SUI |
| Pins objects | none | the coin at a version, plus gas |

The fallback is the flow the spec describes. The gasless path is what Sui's
Address Balances made possible, and it is better on every axis, which is why
most of the sharp edges documented elsewhere apply only to the fallback. See
[`sui-scheme-conformance.md`](sui-scheme-conformance.md).

## Questions this will get

**Can I forge `x-x402-tier: paid`?**
No. The verifier sets it with `OverwriteIfExistsOrAdd`, so a client-supplied
value is replaced rather than appended alongside. Appending would have been the
bug. The demo page has a button that tries it.

**Can I reset the free tier by changing an IP header?**
No. Envoy resolves the real TCP peer and trusts exactly one hop of
`X-Forwarded-For`, and the edge proxy *replaces* that header so a client-supplied
one never survives inward. Setting `xff_num_trusted_hops` higher than the number
of proxies you actually control makes the free tier forgeable, which is the
easiest way to get this wrong. See [`configuring.md`](configuring.md).

**What stops one payment minting many sessions?**
A replay claim keyed on the SHA-256 of the decoded transaction bytes, in a store
shared between the gateway and `/settle`. The chain only rejects re-execution
once settlement lands, which leaves a window this closes.

**What if settlement fails after you have already served me?**
You got that request free. One is noise. A run of them means settlement is
systematically failing and the gateway is quietly giving everything away, which
is what the circuit breaker catches: past a failure rate it refuses payments per
policy and leaves the free tier running. See
[`settlement-failure.md`](settlement-failure.md).

**Why is the verifier doing rate limiting? That is Envoy's job.**
Half right. The verifier has to decide the *tier*, because that depends on
whether a valid payment or session was presented, which only it can evaluate.
Envoy's rate limit filter could then enforce quotas per tier — the descriptors
are in `envoy.yaml`, commented out. It is in-process here because free-tier
exhaustion has to produce a **402 with a machine-readable challenge**, and
Envoy's filter can only return a bare 429.

**Why not just settle before serving?**
Because the scheme sequences it the other way, so a client is not charged for a
request that then fails. That ordering is the reason this uses `ext_proc` at all.
It moves the risk rather than removing it: the server can now serve something it
is not paid for. Which of those two failures you prefer is the actual decision.
