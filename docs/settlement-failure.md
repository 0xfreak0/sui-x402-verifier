# When settlement fails after the resource is served

The failure mode this design carries, what currently happens, and what should be
built. None of the mitigations below are implemented — this is the analysis, not
a changelog.

## What happens today

`ext_proc.rs`, response phase, `Err` branch: log at ERROR, increment
`x402_settlement_after_serve_failures_total`, attach a failure receipt, and
**serve the response anyway**.

Two things already bound the damage, both worth keeping:

- **No session is minted.** Session creation lives only in the `Ok` branch, so
  one failed settlement costs one request, not a 1000-request session.
- **The replay claim is held, not released.** We cannot tell whether settlement
  failed before or after the transaction reached the network, so releasing it
  risks double-charging. Holding is the fail-safe choice for the payer.

## The real risk is correlated failure, not griefing

One-off failure costs one upstream call — noise. The scenario that matters is
the fullnode going down: *every* settlement fails and the gateway silently
degrades into a free public proxy, exactly when that is least affordable.
Nothing currently notices that failures are systemic rather than incidental.

## Planned mitigations, in priority order

1. **Circuit-break on settlement health.** Track failure rate per policy; past
   a threshold, stop deferring — either flip the policy to settle-first
   (`ext_authz` semantics) or reject payments with 503 and serve only the free
   tier. Converts an unbounded outage into a bounded, visible one. Small.

2. **Distinguish the two causes.** Currently identical, actually opposite:

   | Cause | Meaning | Right response |
   |---|---|---|
   | `invalid_transaction_state` | payer killed their own pinned coin | abuse — refuse, mark the payer |
   | `Rpc` / network | our fullnode blipped | our fault — absorb, do not punish a paying user |

3. **Bounded retry** before giving up. Most RPC failures are transient; two
   quick retries would shrink how often 1 and 2 fire at all.

4. **Payer reputation.** A payer whose settlement failed once moves to the
   settle-first lane, so repeat griefing becomes impossible rather than merely
   unprofitable.

## The experiment worth running first

In the response-headers phase, Envoy holds the upstream's headers and has not
sent them downstream — it is blocked on our reply. **If `ImmediateResponse`
works there**, we can withhold the response on settlement failure: the client
gets a 402 instead of the resource, and "served but unpaid" becomes "not
served, not paid".

Unverified. ext_proc's immediate-response support on the response path needs an
actual test. It would not help for non-idempotent upstreams where the work is
already committed, but this gateway's use case is read-heavy RPC, where it
would close the hole rather than merely bound it.

Run this before building 1–4: if it works, it changes what the others need to
do.

## Longer term

The structural fix is to stop making the gateway the enforcement point at all.
Sell decryption rather than access: encrypt the payload under a policy that a
settled payment satisfies, so bypassing the proxy yields ciphertext. Enforcement
moves from "did the gateway check" to "does the chain say you paid", and the
pay-after-service race stops mattering because the bytes were useless without
the receipt.

That only works for content that can be encrypted at rest, so it does nothing
for live RPC pass-through — which is most of what this gateway fronts.
