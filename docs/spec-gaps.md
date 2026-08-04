# Gaps found in the x402 spec while implementing Sui

Recorded against vendored commit `dd927a26` (see `spec/upstream/README.md`).
These are places where the spec does not say enough to implement Sui without
inventing something. Where this project had to choose, the choice and its
reasoning are noted so a future reader can tell a deliberate deviation from an
accident.

## 1. No Sui-specific error codes

`x402-specification-v2.md` §9 defines a closed error vocabulary. The
scheme-specific codes in it are **all EVM-named**:

```
invalid_exact_evm_payload_authorization_valid_after
invalid_exact_evm_payload_authorization_valid_before
invalid_exact_evm_payload_authorization_value_mismatch
invalid_exact_evm_payload_signature
invalid_exact_evm_payload_recipient_mismatch
```

There are no `invalid_exact_sui_payload_*` equivalents, so the failures that
matter most on Sui — bad signature over the transaction, simulated balance
change not crediting `payTo`, amount mismatch — have no precise code.

**What this project does:** map every Sui-specific failure onto a *generic* §9
code (`invalid_payload`, `invalid_payment_requirements`, `invalid_network`, …)
and put the specifics in the human-readable message. Inventing
`invalid_exact_sui_payload_*` names would put strings on the wire that look
exactly like spec codes to a client but are understood by nobody, which is worse
than being vague. See `FacilitatorError::code` in `src/x402.rs`.

**Upstream ask:** define Sui equivalents, or make the EVM-named ones generic.

## 2. `maxTimeoutSeconds` cannot be enforced on-chain on Sui at second granularity

> **Corrected twice while investigating.** First claim: "Sui transactions cannot
> expire" — wrong, they can. Second claim: "so `VALID_DURING` makes this fully
> enforceable" — also wrong. The accurate position is below, verified against
> `sui-sdk-types` 0.3 and testnet `sui-node/1.77.0`. Recorded because the
> difference decides whether enforcement can be delegated to the chain or has to
> be done by the facilitator.

Sui `TransactionData` **does** carry a `TransactionExpiration`:

| Variant | Granularity | Status |
|---|---|---|
| `None` | never expires | the default |
| `Epoch(e)` | one epoch, roughly 24h | works today |
| `ValidDuring { min_epoch, max_epoch, … }` | one epoch — the epochs "must equal current epoch" | works today |
| `ValidDuring { min_timestamp, max_timestamp, … }` | sub-epoch, seconds | **documented "not yet implemented"** |

So the finest expiry the chain will enforce today is **one epoch**. A typical
`maxTimeoutSeconds` of 60 cannot be expressed: the nearest on-chain bound is
roughly a day. `ValidDuring` is also tied to gas payment from *address balances*,
which the scheme's own Appendix lists as in-development, so it is not available
to the coin-object flow the scheme currently specifies.

EVM gets this for free and at second granularity from EIP-3009's
`validAfter` / `validBefore`, and §9 has dedicated error codes for both. Sui has
no equivalent yet.

**What this project does:** enforce the window facilitator-side, recording
first-seen time against the transaction digest in the replay cache. This is
weaker than the EVM guarantee in ways worth being explicit about:

- it binds only the facilitator that saw the payment first;
- it does not survive a restart unless the cache is persistent (ours is, on Redis);
- it is enforcement by policy, not by consensus — a compromised facilitator can
  simply ignore it.

**Upstream ask:** state in `scheme_exact_sui.md` that `maxTimeoutSeconds` is
enforced off-chain on Sui and why, so implementers do not assume EVM-equivalent
safety from an identically-named field; and revisit once sub-epoch timing ships.

## 3. Sequencing assumes the resource server can settle *after* doing the work

`scheme_exact_sui.md` steps 6-10 are: verify → resource server does the work →
settle. That ordering protects the client: they are only charged once the
resource has actually been produced.

An Envoy `ext_authz` service is a **pre-upstream** filter. It runs before the
request reaches the backend and cannot observe the response, so it can only
settle *before* the work happens — the opposite of what the scheme asks for.

**Resolved in this implementation.** `ext_proc` is a bidirectional stream, one
per HTTP request, carrying request headers *and* response headers. That makes the
spec's ordering achievable at the gateway: verify on the way in, hold the
verified payment as stream-local state, settle on the way out only after a 2xx.
It is the default here, and `ext_authz` is kept only as a fallback for gateways
that do not support ext_proc.

Still worth raising upstream: the spec assumes the resource server can call the
facilitator twice around its own work, which silently rules out the entire class
of pre-upstream authorization filters (`ext_authz`, Kong plugins, NGINX
`auth_request`). Those are an obvious way to deploy x402, and an implementer
reaching for one will produce a conformant-looking service with the payment
ordering inverted and no indication anything is wrong. Naming the constraint —
and that response-path processing is required — would prevent that.
