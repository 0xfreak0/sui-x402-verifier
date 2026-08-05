# Draft issue: the Sui `exact` scheme never says how `maxTimeoutSeconds` is enforced

**Repo:** coinbase/x402
**Against:** `specs/x402-specification-v2.md` §5.1.2, `specs/schemes/exact/scheme_exact_sui.md`
**Status:** DO NOT FILE. This repo is an exploratory prototype; nothing here
is to be opened against coinbase/x402 or any other external repo. Kept as
notes on where the spec is underspecified, for our own reference only.

> **Corrected 2026-08-04.** An earlier draft claimed Sui transactions cannot
> expire (wrong — they can), then that `VALID_DURING` timestamps make the field
> fully enforceable (also wrong — those are documented "not yet implemented").
> The accurate position is below, verified against `sui-sdk-types` 0.3 and
> testnet `sui-node/1.77.0`.

---

### Summary

`PaymentRequirements.maxTimeoutSeconds` is required, but on Sui the chain cannot
enforce a window at second granularity today. The finest available expiry is one
epoch (~24h). The scheme does not say this, so implementers reasonably assume the
field carries the same weight it does on EVM, where EIP-3009 enforces it to the
second.

### Detail

Sui's `TransactionExpiration` supports:

| Variant | Granularity | Status |
|---|---|---|
| `None` | never expires | the default |
| `Epoch(e)` | one epoch, ~24h | works today |
| `ValidDuring { min_epoch, max_epoch, … }` | one epoch — epochs "must equal current epoch" | works today |
| `ValidDuring { min_timestamp, max_timestamp, … }` | seconds | **"not yet implemented"** per `sui-sdk-types` |

Two consequences:

1. A `maxTimeoutSeconds` of 60 has no on-chain expression. The nearest bound the
   validators will enforce is roughly a day.
2. `ValidDuring` is additionally tied to gas payment from *address balances*,
   which this scheme's own Appendix lists as in-development — so it is not
   available to the coin-object flow the scheme currently specifies.

The scheme is also silent on whether a client should set an expiration at all,
so a conformant client may send `None` and hold an authorization valid forever,
and two facilitators will disagree about whether to accept it.

### What we do meanwhile

Enforce the window facilitator-side: record first-seen time against the
transaction digest in a replay cache, and refuse the payload once
`maxTimeoutSeconds` has elapsed. This is policy, not consensus — it binds only
the facilitator that saw the payment first, and a compromised one can ignore it.

### Suggested resolution

Short term, state in `scheme_exact_sui.md` that `maxTimeoutSeconds` is enforced
**off-chain** on Sui, and say why, so implementers do not assume the
EVM-equivalent guarantee from an identically-named field.

Longer term, once `ValidDuring`'s sub-epoch timestamps are implemented, specify
that clients must set them within the advertised window and that facilitators
must reject payments that do not — at which point Sui gains the same property
EIP-3009 gives EVM.
