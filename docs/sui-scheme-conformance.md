# Conformance against `scheme_exact_sui.md`

Checked line by line against the vendored spec
(`spec/upstream/scheme_exact_sui.md`, `coinbase/x402` @ `dd927a26`) and the code
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
| 3 | Simulate: would succeed, not already executed | **P** | `SimulateTransaction`, rejecting a non-success status. "Already executed" is covered only insofar as the simulation reports it; we do not separately query the ledger for the digest |
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

**Gap in step 3, demonstrated.** Simulation does not reject an authorization
whose input coins have since been spent. Measured on testnet:

1. Build and sign a payment pinning USDC coin `0x3a4d…`. `/verify` → `isValid: true`.
2. Spend that same coin in an unrelated transaction (`2WUTtXX…`, Success).
3. `/verify` again → **still `isValid: true`**.
4. `/settle` → fails: `ExecuteTransaction: Client specified an invalid argument`.

So verification passes on an authorization that is already dead. Execution
enforces object versions; simulation, at least as we call it, does not. This
matters most on the deferred-settlement path, where the gap between verify and
settle is exactly the window an upstream request takes.

Two things would narrow it, neither yet done:

- probe the ledger for the transaction digest and for the input objects' current
  versions during verification, rather than trusting the simulation alone;
- use `sui-rpc`'s `execute_transaction_and_wait_for_checkpoint`, which handles
  duplicate submissions by probing the ledger.

Note this is not a flaw the scheme's ordering introduces so much as one it
*exposes*: see "The pay-after-service window" below.

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

This matters for one reason worth recording: an earlier design document for this
project assumed Address Balances had shipped and concluded that settlement would
be gas-free for everyone. It has not, and it is not. The current scheme requires
a fully-formed signed transaction where the client pays gas (observed:
~0.0023 SUI on a testnet transfer) unless a facilitator sponsors it.

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

So the ordering does not shift risk from the client to nobody — it shifts risk
from the client **to the server**:

| Ordering | Client risk | Server risk |
|---|---|---|
| settle first (`ext_authz`) | charged for a request that then fails | none |
| settle after (`ext_proc`, spec order) | none | resource served, payment now dead |

The exposure is bounded by how long the work takes. A 50 ms upstream call is a
50 ms window; a 30-second query is a 30-second window during which a motivated
client can invalidate the authorization deterministically, not just by luck.

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

Of the four verification steps the scheme defines, three are fully implemented
and one (step 3, "not already executed") is partial. The payload shape, the
settlement mechanism and the network check are conformant. The two `N`s are
sponsorship, which is deliberately out of scope and correctly advertised as
absent.

The most material gap is step 3's already-executed check.
