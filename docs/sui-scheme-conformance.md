# Conformance against `scheme_exact_sui.md`

Checked line by line against the vendored spec
(`spec/upstream/scheme_exact_sui.md`, `x402-foundation/x402`, canonical since the spec moved to the foundation) and the code
as of the current commit. Every claim below is either backed by a named test or
marked as unverified.

Legend: **Y** conformant · **P** partial · **N** not implemented · **D**
deliberate deviation

---

## Protocol sequencing (§ Protocol Sequencing, steps 1-11)

| # | Spec step | | Where / note |
|---|---|---|---|
| 1 | Client requests, gets payment-required | **Y** | `auth.rs` free-tier exhaustion → `PaymentRequired` |
| 2 | Client queries RPC for its coin objects | **Y** | Client-side. `scripts/lib/build-payment.sh` does this via the `sui` CLI |
| 3 | Client optionally uses a sponsorship service | **N** | We advertise `extra.gasStation` when configured but implement no gas station. See Sponsorship below |
| 4 | Client crafts and signs a transaction | **Y** | Client-side |
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

Tests: `x402::spec_sui_exact_payload_roundtrips`,
`x402::spec_payment_payload_sui_roundtrips` — both round-trip the spec's own
JSON examples, so drift fails CI.

## Verification (§ Verification, steps 1-4)

| # | Spec step | | Implementation |
|---|---|---|---|
| 1 | Network is the agreed-upon chain | **Y** | `Facilitator::check_terms` compares against the facilitator's **own** configured network, not merely the client's claim against the supplied requirements |
| 2 | Signature is valid over the provided transaction | **Y** | `SignatureVerificationService.VerifySignature`, with the address recovered from the BCS-decoded transaction rather than taken from the client |
| 3 | Simulate: would succeed, not already executed | **Y** | `SimulateTransaction` rejecting a non-success status, **plus** an explicit check that every pinned input object still exists at its pinned version — simulation alone does not enforce that |
| 4 | `payTo` sees a balance change equal to `amount` in `asset` | **Y** | `sui::assert_credits` over the simulation's `balance_changes`, summed per (address, coin type), compared for **equality** |

Step 4 notes:

- **Equality, not `>=`.** The scheme is named `exact`; silently accepting an
  overpayment would make the advertised price a suggestion.
- **The recipient's delta is read, not the sender's**, because the sender's also
  includes gas and is therefore not a measure of what was paid.
- Multiple credits to the same recipient are summed rather than first-match.

Tests: `sui::credits_the_exact_amount_to_the_right_address_and_asset`,
`rejects_an_underpayment`, `rejects_an_overpayment_too`,
`rejects_payment_to_the_wrong_address`, `rejects_payment_in_the_wrong_asset`,
`sums_multiple_credits_to_the_same_recipient`. Validated live on testnet against
a wallet-signed transfer, including the four negative cases.

**Step 3 needed more than simulation.** Simulation does *not* reject an
authorization whose input coins have since been spent. Measured on testnet
before the fix:

1. Sign a payment pinning USDC coin `0x3a4d…`. `/verify` → `isValid: true`.
2. Spend that coin in an unrelated transaction (Success).
3. `/verify` again → **still `isValid: true`**.
4. `/settle` → `ExecuteTransaction: Client specified an invalid argument`.

That is free service with no race required: spend the coin first, then present
the dead authorization, be verified, be served, and watch settlement fail.

`SuiVerifier::assert_inputs_are_live` now reads every pinned input — owned and
receiving inputs from the PTB, plus the gas objects — and confirms each still
exists at the pinned version. Shared inputs are skipped, since consensus
versions those at execution rather than the client pinning them. A `NotFound`
object is treated as spent rather than as an RPC failure.

Re-measured after the fix: step 3 now returns `isValid: false`
(`invalid_transaction_state`) once the coin is spent.

This matters for more than tidiness — see the next section.

## Settlement (§ Settlement)

| Requirement | | Note |
|---|---|---|
| Facilitator broadcasts the transaction with the client's signature | **Y** | `ExecuteTransaction` with the client's `UserSignature`, unmodified |
| Report the result to the resource server | **Y** | `SettlementResponse` with the on-chain digest |

`settle` re-runs verification before broadcasting. The scheme assumes
verification already happened, but `/settle` is a callable endpoint and must not
become a way to get an unchecked transaction broadcast.

Validated live: digest `wcDro2qkLrmhckT1QAGZefHpBuEw8XNQPB2A42nrof9`, checkpoint
368080349, recipient credited exactly 10 base units.

## Sponsorship (§ Appendix, Sponsored Transactions)

| Requirement | | Note |
|---|---|---|
| Advertise support via `PaymentRequirements.extra.gasStation` | **Y** | Populated when `gas_station` is configured |
| Run the interactive gas-station protocol | **N** | Out of scope |
| Facilitator adds its own signature at settle time | **N** | Out of scope |

Deliberate: sponsorship requires a funded hot wallet, which changes the security
posture from "this service holds no keys" — currently checkable via the empty
`signers` map in `/supported` — to "this service holds keys". Not worth it for a
demo. The advertisement path exists so the field is not silently absent.

## Future work referenced by the spec (§ Appendix, Future Work)

The spec lists **Address Balances** as in-development: it would remove the
storage cost of creating a coin object, make sponsorship non-interactive, and
potentially enable EIP-3009-style authorizations on Sui.

**The spec is out of date here, and it changes the scheme materially.**
Address Balances has shipped: `0x2::coin::redeem_funds` and
`0x2::coin::send_funds` exist on both testnet and mainnet, and
`TransactionExpiration::ValidDuring` — whose documented purpose is enabling gas
payment from address balances — is live except for its sub-epoch timestamp
fields.

So gasless stablecoin payment works today. Measured on testnet through this
gateway, digest `HNSWvtuWPidbRFCpDQU8AfVf1Nce5dQP3Zo6SsxLeRAV`:
`computation_cost: 0, storage_cost: 0`, the payer holding no SUI at all. That
supersedes an earlier claim in this document — twice corrected now — that
settlement necessarily costs the client ~0.0023 SUI.

Three conditions apply, none of them in the spec text:

1. The transfer must be **at least 0.01 USDC**; below that it does not execute.
2. Funds must already be in the sender's **address balance**, not coin objects.
   Moving them there costs gas once.
3. The transaction must carry `ValidDuring` with a nonce. Address-balance gas
   removes the replay protection that came from mutating a gas coin object, so
   uniqueness has to be supplied explicitly or validators reject it.

This also narrows the vulnerability recorded above. The spent-input problem is a
property of coin-object pinning; a withdrawal pins nothing, so on the gasless
path there is no authorization to invalidate. `assert_inputs_are_live` still
guards the fallback, which is the only path that can pin anything.

## The pay-after-service window

The scheme's sequencing (verify → work → settle) protects the client: they are
only charged once the resource has been produced. It is worth being precise
about what it does **not** do, because "settle afterwards" sounds like it binds
the payer and it does not.

**Nothing enforces payment after the fact.** A Sui payment authorization is a
signed transaction pinning specific coin objects *at specific versions*. Between
verify and settle, the payer can spend those coins in any other transaction,
and the authorization becomes permanently unexecutable. Demonstrated above: the
settle failed with `Client specified an invalid argument` after the payer moved
the pinned coin.

**This applies to the coin-object path only.** A gasless payment (0.01 USDC and
above) withdraws from an address balance and pins no objects at all, so there is
nothing for the payer to spend and no authorization to invalidate. Everything
below describes the sub-cent fallback.

So the ordering does not shift risk from the client to nobody — it shifts risk
from the client **to the server**:

| Ordering | Client risk | Server risk |
|---|---|---|
| settle first (`ext_authz`) | charged for a request that then fails | none |
| settle after (`ext_proc`, spec order) | none | resource served, payment now dead |

The exposure is bounded by how long the work takes, and that bound only means
something because verification now rejects already-dead authorizations. Before
that fix there was no race at all: a client could spend the coin first and still
verify. With it, invalidating a payment means landing a competing transaction
*inside the upstream-latency window* — on the order of 100 ms for a GraphQL
query — against Sui finality of roughly 400 ms. That is a losing race in the
general case rather than a free lunch.

It is still a race, not a guarantee. A slow upstream widens it, which is a good
reason to keep expensive endpoints on `ext_authz` or to cap upstream timeouts.

**Sessions reduce this by roughly the quota factor.** One settlement covers a
whole session, so the window opens once per session rather than once per
request. At the default 1000-request quota, a client racing successfully steals
one session's worth of access, and cannot repeat it without signing a fresh
payment that must itself settle.

This is why the residual risk is stated plainly rather than described as solved,
and why `x402_settlement_after_serve_failures_total` exists as an alert: it is
the metric that counts exactly this happening.

## Where we deviate, and why

| Deviation | Reason |
|---|---|
| `ext_authz` path settles before the work | The filter is pre-upstream and cannot observe the response. `ext_proc` is the default and does not have this problem |
| Sessions: one payment buys many requests | The scheme describes per-request payment. A quota-and-window session is a superset, and settlement latency makes per-request settlement impractical at gateway speed. Sessions are declared as an x402 extension (§5.1.2) rather than invented as a private header |
| `maxTimeoutSeconds` enforced off-chain | Sui's finest on-chain expiry is one epoch (~24h), so a 60-second window has no on-chain expression. See `spec-gaps.md` |
| Sui failures map to generic §9 error codes | No Sui-specific codes exist upstream; inventing spec-shaped names would be worse than being generic. See `upstream-issues/01` |
| gRPC reflection and health are not gated | Clients attach headers to the reflection call, so gating it consumed the payment and the real call was then refused as a replay |

## Not covered by the Sui scheme, added anyway

- **Replay protection.** The scheme leans on the chain rejecting re-execution,
  which only binds once settlement lands. Before that, one signature could mint
  many sessions — certainly in stub mode, and racily even with real settlement.
  Payments are claimed by decoded-transaction digest in a store shared between
  the gateway and `/settle`.
- **Per-route pricing and per-route session scoping**, so a session bought on a
  cheap route cannot unlock an expensive one.

## Summary

All four verification steps the scheme defines are implemented. The payload shape, the
settlement mechanism and the network check are conformant. The two `N`s are
sponsorship, which is deliberately out of scope and correctly advertised as
absent.

All four verification steps are now implemented. The remaining exposure is the
pay-after-service window described above, which is inherent to the spec's
ordering rather than to this implementation, and is bounded by upstream latency
against chain finality.
