# Conformance against `scheme_exact_sui.md`

Checked line by line against the vendored spec (`spec/upstream/scheme_exact_sui.md`,
from `x402-foundation/x402`) and the code as of the current commit. Every claim
here is either backed by a named test or marked as unverified.

This is self-assessment. Nobody upstream reviewed it, and there is no conformance
suite to run — the x402 repo ships no test vectors. What it rests on is that each
claim is individually checkable: the spec's own JSON examples are extracted into
`tests/fixtures/`, so a spec change that alters a shape fails CI rather than
passing quietly.

Legend: **Y** conformant · **P** partial · **N** not implemented · **D**
deliberate deviation

---

## Read this first: there are two payment paths

The scheme describes one flow. This implements two, chosen by price, and almost
every interesting property below differs between them.

| | **Gasless** (default) | **Coin object** (fallback) |
|---|---|---|
| When | `amount` ≥ 0.01 USDC | below that |
| Funds from | sender's address balance | a selected `Coin` object |
| Move calls | `redeem_funds` → `send_funds` | `split_coins` → `transfer_objects` |
| Gas | **zero** — payer needs no SUI | payer pays, ~0.0023 SUI observed |
| Objects pinned | **none** | the coin, at a version, plus gas objects |
| Expiration | `ValidDuring` + nonce, mandatory | `None` |
| Can the payer kill it after being served? | **no** | yes — see [the window](#the-pay-after-service-window) |

The spec was written before Sui's Address Balances shipped and describes only
the second. The first is what the code does by default, and it removes the two
worst properties of the scheme as specified.

**Measured, not asserted.** Gasless settlement through this gateway, testnet
digest `HNSWvtuWPidbRFCpDQU8AfVf1Nce5dQP3Zo6SsxLeRAV`: `computation_cost: 0,
storage_cost: 0`, payer holding no SUI. Coin-object settlement for comparison,
digest `GHmy3CqMPg2UGykt6igADXmfYGYxF7NXqrf7Nnc3LTFG`: 2,345,504 MIST.

---

## Protocol sequencing (§ Protocol Sequencing, steps 1-11)

| # | Spec step | | Where / note |
|---|---|---|---|
| 1 | Client requests, gets payment-required | **Y** | `auth.rs` free-tier exhaustion → `PaymentRequired` |
| 2 | Client queries RPC for its coin objects | **D** | Only on the fallback (`payclient::pick_coin`). The gasless path queries nothing — a withdrawal names an amount, not an object |
| 3 | Client optionally uses a sponsorship service | **N** | See [Sponsorship](#sponsorship--appendix-sponsored-transactions), which gasless makes largely moot |
| 4 | Client crafts and signs a transaction | **Y** | Client-side, `payclient::build_payment` |
| 5 | Client resends with `PaymentPayload` | **Y** | `PAYMENT-SIGNATURE` header, HTTP transport |
| 6 | Resource server passes payload to facilitator for verification | **Y** | In-process call, or `POST /verify` for an external resource server |
| 7 | Resource server does the work | **Y** | Envoy proxies to the upstream |
| 8 | Resource server requests settlement | **Y** | `ext_proc` response phase, or `POST /settle` |
| 9 | Facilitator adds its sponsor signature if sponsorship was used | **N** | No sponsorship |
| 10 | Facilitator submits the transaction, reports the result | **Y** | `sui.rs::settle` → `ExecuteTransaction` |
| 11 | Resource server returns the response | **Y** | |

**Ordering caveat.** Steps 6-8 place the work *between* verify and settle. That
holds on the `ext_proc` path and on `/verify` + `/settle`. It does **not** hold on
the `ext_authz` path, which is pre-upstream and therefore settles before the work
(**D**, documented in the README; `ext_proc` is the default for this reason).

## Payload shape (§ PaymentPayload `payload` Field)

| Requirement | | Note |
|---|---|---|
| `signature`: user signature over the transaction | **Y** | `SuiExactPayload::signature` |
| `transaction`: base64-encoded Sui transaction | **Y** | `SuiExactPayload::transaction` |
| No other fields | **Y** | An earlier version carried `transactionBytes` / `signatures[]` / `payer`; none were spec names |

Identical on both paths — the payload is opaque bytes, and the spec does not
constrain what the transaction contains beyond what verification checks.

Tests: `x402::spec_sui_exact_payload_roundtrips`,
`x402::spec_payment_payload_sui_roundtrips` — both round-trip the spec's own
JSON examples, so drift fails CI.

## Verification (§ Verification, steps 1-4)

| # | Spec step | | Implementation |
|---|---|---|---|
| 1 | Network is the agreed-upon chain | **Y** | `Facilitator::check_terms` compares against the facilitator's **own** configured network, not merely the client's claim against the supplied requirements |
| 2 | Signature is valid over the provided transaction | **Y** | `SignatureVerificationService.VerifySignature`, with the address recovered from the BCS-decoded transaction rather than taken from the client |
| 3 | Simulate: would succeed, not already executed | **Y** | `SimulateTransaction` rejecting a non-success status, plus a liveness check on any pinned inputs — see below |
| 4 | `payTo` sees a balance change equal to `amount` in `asset` | **Y** | `sui::assert_credits` over the simulation's `balance_changes`, summed per (address, coin type), compared for **equality** |

All four apply unchanged to both paths. Step 4 in particular works on gasless
payments because `send_funds` still produces a `balance_changes` entry crediting
the recipient — confirmed on the digest above.

Step 4 notes:

- **Equality, not `>=`.** The scheme is named `exact`; silently accepting an
  overpayment would make the advertised price a suggestion.
- **The recipient's delta is read**, because the sender's also includes gas on
  the fallback path and is therefore not a measure of what was paid.
- Multiple credits to the same recipient are summed rather than first-match.

Tests: `sui::credits_the_exact_amount_to_the_right_address_and_asset`,
`rejects_an_underpayment`, `rejects_an_overpayment_too`,
`rejects_payment_to_the_wrong_address`, `rejects_payment_in_the_wrong_asset`,
`sums_multiple_credits_to_the_same_recipient`. Validated live on testnet against
a wallet-signed transfer, including the four negative cases.

### Step 3 needed more than simulation — on the fallback path

Simulation does *not* reject an authorization whose input coins have since been
spent. Measured on testnet before the fix:

1. Sign a payment pinning USDC coin `0x3a4d…`. `/verify` → `isValid: true`.
2. Spend that coin in an unrelated transaction (Success).
3. `/verify` again → **still `isValid: true`**.
4. `/settle` → `ExecuteTransaction: Client specified an invalid argument`.

That is free service with no race required: spend the coin first, then present
the dead authorization, be verified, be served, and watch settlement fail. Any
facilitator that verifies by simulating alone has this.

`SuiVerifier::assert_inputs_are_live` reads every pinned input — owned and
receiving inputs from the PTB, plus the gas objects — and confirms each still
exists at the pinned version. Shared inputs are skipped, since consensus versions
those at execution rather than the client pinning them. A `NotFound` object is
treated as spent rather than as an RPC failure.

Re-measured after the fix: step 3 returns `isValid: false`
(`invalid_transaction_state`) once the coin is spent.

**A gasless payment pins nothing**, so it has no inputs to go stale and the check
is a no-op for it. The finding remains true of the scheme as specified, and the
guard remains necessary for the fallback — but it is not a property of how this
gateway is normally paid.

## Settlement (§ Settlement)

| Requirement | | Note |
|---|---|---|
| Facilitator broadcasts the transaction with the client's signature | **Y** | `ExecuteTransaction` with the client's `UserSignature`, unmodified |
| Report the result to the resource server | **Y** | `SettlementResponse` with the on-chain digest |

`settle` re-runs verification before broadcasting. The scheme assumes
verification already happened, but `/settle` is a callable endpoint and must not
become a way to get an unchecked transaction broadcast.

Validated live on both paths: coin-object digest
`wcDro2qkLrmhckT1QAGZefHpBuEw8XNQPB2A42nrof9` (checkpoint 368080349, recipient
credited exactly 10 base units) and gasless digest
`4WZezjRarhwhjLPHGixDbFZSCYQvqcyRcrYMawansvVz` through the deployed gateway.

## Address Balances — the spec's "future work" has shipped

The spec's appendix lists **Address Balances** as in-development, and says it
would remove the storage cost of creating a coin object, make sponsorship
non-interactive, and potentially enable EIP-3009-style authorizations on Sui.

**All of that is now available.** `0x2::coin::redeem_funds` and
`0x2::coin::send_funds` exist on testnet and mainnet, and
`TransactionExpiration::ValidDuring` — whose documented purpose is enabling gas
payment from address balances — is live except for its sub-epoch timestamp
fields.

Three conditions apply, none of them in the spec text, all of them discovered by
experiment:

1. The transfer must be **at least 0.01 USDC**; below that it does not execute
   at all, silently falling back to the coin-object path.
2. Funds must already be in the sender's **address balance**. Moving them there
   costs gas once, and `sui client balance` reports the total and the
   coin-object figure separately — the difference is what is spendable this way.
3. The transaction must carry `ValidDuring` with a nonce and epoch bounds.
   Address-balance gas removes the replay protection that came from mutating a
   gas coin object, so uniqueness has to be supplied explicitly or validators
   reject it.

Gas price and budget must both be literally zero, and no gas objects may be
attached. `--stateless` alone is not enough — that draws gas *from the address
balance*, which is a different feature and still charges.

Only three Move functions are permitted on this path (`withdrawal_split`,
`redeem_funds`, `send_funds`) and the transaction may not write any object,
which is why the payment sends into the recipient's address balance instead of
splitting a coin and transferring it.

## Sponsorship (§ Appendix, Sponsored Transactions)

| Requirement | | Note |
|---|---|---|
| Advertise support via `PaymentRequirements.extra.gasStation` | **Y** | Populated when `gas_station` is configured |
| Run the interactive gas-station protocol | **N** | Out of scope |
| Facilitator adds its own signature at settle time | **N** | Out of scope |

Deliberate, and less costly than it was — but not free, and the reason this was
originally skipped does not fully hold.

Sponsorship exists in the spec so a payer without SUI can still pay. The gasless
path removes that need in **steady state**: at or above the floor, a payer
spending from their address balance needs no SUI ever again. It does not remove
it at **cold start**. Gasless spends from the address balance, USDC arrives as
coin objects, and moving funds across is a `0x2::coin::send_funds` that costs
gas. A payer holding only stablecoins therefore cannot bootstrap, which is
precisely the case sponsorship covers.

So the honest position is:

| Payer holds | Gasless | Coin object | Sponsored |
|---|---|---|---|
| Funded address balance | Y | — | — |
| Coin objects **and** SUI | N | Y | Y |
| Coin objects, **no SUI** | N | N | **only this** |

The client falls through the first two automatically (`payclient::build_payment`),
so rows one and two need nothing. Row three needs a gas station, and for an
agent holding only stablecoins row three is the normal state rather than an edge
case.

`WithdrawFrom::Sponsor` exists in the SDK for a non-interactive version, which is
the shape to build if this is ever wanted — the spec's own appendix says Address
Balances should make the interactive protocol unnecessary.

Implementing it would mean holding a funded hot wallet, which changes the
security posture from "this service holds no keys" — checkable via the empty
`signers` map in `/supported` — to "this service holds keys". The advertisement
path exists so the field is not silently absent.

## The pay-after-service window

The scheme's sequencing (verify → work → settle) protects the client: they are
only charged once the resource has been produced. It is worth being precise
about what it does **not** do, because "settle afterwards" sounds like it binds
the payer.

**On the coin-object path, nothing enforces payment after the fact.** A
coin-object authorization is a signed transaction pinning specific objects at
specific versions. Between verify and settle the payer can spend those coins in
any other transaction and the authorization becomes permanently unexecutable —
demonstrated above, where settle failed with `Client specified an invalid
argument` after the payer moved the pinned coin.

So on that path the ordering shifts risk from the client to the server:

| Ordering | Client risk | Server risk |
|---|---|---|
| settle first (`ext_authz`) | charged for a request that then fails | none |
| settle after (`ext_proc`, spec order) | none | resource served, payment now dead |

The exposure is bounded by how long the work takes, and that bound only means
something because verification rejects already-dead authorizations. Before that
fix there was no race at all. With it, invalidating a payment means landing a
competing transaction *inside the upstream-latency window* — around 70 ms
observed for a GraphQL query — against Sui finality of roughly 400 ms. A losing
race in the general case rather than a free lunch, though a slow upstream widens
it, which is a reason to cap upstream timeouts.

**On the gasless path this does not arise.** A withdrawal pins no objects, so
there is nothing the payer can spend to invalidate their own authorization. The
`ValidDuring` epoch bound is the only way it expires, and that is on the order of
a day.

Settlement can still fail for reasons unrelated to the payer — an unreachable
fullnode, a congested network — so
`x402_settlement_after_serve_failures_total` remains the alert for a resource
served and not paid for, on either path. See
[`settlement-failure.md`](settlement-failure.md) for what should be built around it.

**Sessions reduce the exposure by roughly the quota factor.** One settlement
covers a whole session, so the window opens once per session rather than once per
request.

## Where we deviate, and why

| Deviation | Reason |
|---|---|
| Gasless payments as the default | The spec describes only the coin-object flow, written before Address Balances shipped. The gasless path is strictly better for the payer and removes two of the scheme's sharpest edges |
| `ext_authz` path settles before the work | The filter is pre-upstream and cannot observe the response. `ext_proc` is the default and does not have this problem |
| Sessions: one payment buys many requests | The scheme describes per-request payment. Below 0.01 USDC a gasless transfer will not execute, so sub-cent per-request pricing falls back to coin objects and makes the payer find SUI for gas; a session keeps the effective price below a cent while every settlement stays above the gasless floor. Declared as an x402 extension (§5.1.2) rather than invented as a private header |
| `maxTimeoutSeconds` enforced off-chain | Sui's finest on-chain expiry is one epoch (~24h). `ValidDuring` carries `min_timestamp`/`max_timestamp` fields that would fix this, documented as not yet implemented. See `spec-gaps.md` |
| Sui failures map to generic §9 error codes | No Sui-specific codes exist upstream; inventing spec-shaped names would be worse than being generic. See `upstream-issues/01` |
| gRPC reflection and health are not gated | Clients attach headers to the reflection call, so gating it consumed the payment and the real call was then refused as a replay |

## Not covered by the Sui scheme, added anyway

- **Replay protection.** The scheme leans on the chain rejecting re-execution,
  which only binds once settlement lands. Before that, one signature could mint
  many sessions. Payments are claimed by decoded-transaction digest in a store
  shared between the gateway and `/settle`.
- **Per-route pricing and per-route session scoping**, so a session bought on a
  cheap route cannot unlock an expensive one.
- **A gRPC transport binding.** The spec defines HTTP, MCP and A2A transports and
  nothing for gRPC. Denials are framed as trailers-only responses carrying
  `grpc-status: 8` (`RESOURCE_EXHAUSTED`, what gRPC maps 429 to), because a
  plain 402 reaches a gRPC client as an opaque `code = Unknown`. x402's headers
  are base64 JSON and so survive as gRPC metadata unchanged.

## Summary

All four verification steps the scheme defines are implemented, on both payment
paths. The payload shape, the settlement mechanism and the network check are
conformant. The two `N`s are sponsorship, deliberately out of scope and correctly
advertised as absent — and largely unnecessary now that the payer needs no gas.

The one exposure inherent to the spec's ordering — a served resource whose
payment is then killed — applies only to sub-cent payments on the coin-object
path. Above the floor there is nothing pinned to invalidate.

The spec itself is the thing most out of date here: it describes a flow requiring
coin selection, client-paid gas, and an interactive gas station, all of which
Address Balances has made avoidable.
