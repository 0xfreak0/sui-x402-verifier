# Draft issue: `maxTimeoutSeconds` is unenforceable on Sui

**Repo:** coinbase/x402
**Against:** `specs/x402-specification-v2.md` §5.1.2, `specs/schemes/exact/scheme_exact_sui.md`
**Status:** draft — not yet filed

---

### Summary

`PaymentRequirements.maxTimeoutSeconds` is a required field, but the Sui `exact`
scheme provides no mechanism to enforce it. A signed Sui payment authorization
has no expiry, so it stays valid indefinitely.

### Detail

On EVM the field is enforceable *by the chain*: an EIP-3009 authorization
carries `validAfter` / `validBefore`, and `transferWithAuthorization` reverts
outside that window. §9 has dedicated codes for both violations. The guarantee
does not depend on any facilitator behaving well.

Sui `TransactionData` has no equivalent. It carries a sender, gas data, and
input object references — no timestamp, no epoch bound, no expiry. A transaction
signed once remains submittable until its input objects are consumed. So:

- A client that signs a payment and never sends it holds an authorization that
  stays good indefinitely.
- `maxTimeoutSeconds` is advertised to the client as though it constrains
  something, and does not.

`scheme_exact_sui.md` does not mention the field at all — neither how to enforce
it nor that it cannot be enforced.

### What an implementer is left to do

Facilitator-side bookkeeping: record first-seen time keyed on transaction
digest, and refuse the payload once the window elapses. That is strictly weaker
than the EVM guarantee in ways worth stating in the spec:

- It binds only the facilitator that saw the payment first. A second facilitator
  accepting the same requirements has no shared state and will accept it.
- It does not survive a facilitator restart unless the cache is persistent.
- It is enforcement by policy, not by the chain — a misbehaving or compromised
  facilitator can simply ignore it.

Note the object-version pinning that makes Sui transactions non-replayable
*on-chain* only binds once settlement lands. Before that, nothing stops N
concurrent submissions of the same authorization from being accepted by N
resource servers.

### Suggested resolution

1. State in `scheme_exact_sui.md` that `maxTimeoutSeconds` is enforced off-chain
   on Sui, and specify the expected mechanism (digest + first-seen cache) so
   implementations agree; **and**
2. Note the weaker guarantee explicitly, so implementers do not assume
   EVM-equivalent safety from an identically-named field.

Longer term, the "Address Balances" work referenced in the scheme's Appendix is
described as potentially enabling EIP-3009-style authorizations on Sui, which
would make the field enforceable on-chain. Worth linking the two.
