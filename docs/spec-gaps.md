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

## 2. No way to enforce `maxTimeoutSeconds` on Sui

`PaymentRequirements.maxTimeoutSeconds` is required, and on EVM it is enforceable
because EIP-3009 authorizations carry `validAfter`/`validBefore` — the *chain*
rejects a stale authorization.

Sui `TransactionData` has no expiry field. A signed transaction stays valid until
its input objects are consumed, so a payment authorization signed once is
replayable indefinitely as far as the client's signature is concerned. The Sui
scheme document does not say how a facilitator should enforce the window.

**Consequence:** `maxTimeoutSeconds` is currently advertised and unenforceable
on-chain. Any enforcement is facilitator-side bookkeeping — recording first-seen
time per transaction digest and refusing the payload afterwards — which is
strictly weaker than the EVM guarantee: it binds only this facilitator, and a
second facilitator, or a restarted one with no shared state, would accept the
same authorization again.

**Upstream ask:** state the expected enforcement mechanism, and say plainly that
it is off-chain on Sui so implementers do not assume EVM-equivalent safety.

## 3. Sequencing assumes the resource server can settle *after* doing the work

`scheme_exact_sui.md` steps 6-10 are: verify → resource server does the work →
settle. That ordering protects the client: they are only charged once the
resource has actually been produced.

An Envoy `ext_authz` service is a **pre-upstream** filter. It runs before the
request reaches the backend and cannot observe the response, so it can only
settle *before* the work happens. See the README for the consequence and the
`ext_proc` shape that would fix it.

This is a deployment-topology gap rather than a spec defect, but the spec would
be more useful if it named the constraint, since gateway-level enforcement is an
obvious way to deploy x402.
