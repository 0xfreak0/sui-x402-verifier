# Draft issue: `exact` on Sui has no scheme-specific error codes

**Repo:** coinbase/x402
**Against:** `specs/x402-specification-v2.md` §9, `specs/schemes/exact/scheme_exact_sui.md`
**Status:** draft — not yet filed

---

### Summary

§9's error vocabulary contains scheme-specific codes for EVM only. Implementing
`exact` on Sui, the failures that matter most have no code to report.

### Detail

The scheme-specific entries in §9 are all EVM-named:

```
invalid_exact_evm_payload_authorization_valid_after
invalid_exact_evm_payload_authorization_valid_before
invalid_exact_evm_payload_authorization_value_mismatch
invalid_exact_evm_payload_signature
invalid_exact_evm_payload_recipient_mismatch
```

`scheme_exact_sui.md` defines four verification steps, three of which can fail
in a Sui-specific way with no corresponding code:

| Sui verification step | Closest §9 code | Precise? |
|---|---|---|
| 2. signature valid over the transaction | `invalid_payload` | no — cannot distinguish a bad signature from a malformed payload |
| 3. simulation succeeds / not already executed | `invalid_transaction_state` | partially |
| 4. `payTo` sees a balance change of exactly `amount` | `invalid_payment_requirements` | no — this is the core payment check and it has no code of its own |

Step 4 is the one that makes the exchange a payment rather than a handshake, and
a client that fails it cannot be told *why* in machine-readable form.

### Why not just add `invalid_exact_sui_payload_*` locally

Because a client cannot tell a locally-invented code from a standard one. A
string like `invalid_exact_sui_payload_signature` looks exactly like a §9 code
and is understood by nobody, which is worse than being deliberately generic.

Our implementation therefore maps every Sui-specific failure onto a generic §9
code and puts the specifics in the human-readable message — losing machine
readability precisely where it is most useful.

### Suggested resolution

Either:

1. **Define Sui equivalents** — `invalid_exact_sui_payload_signature`,
   `invalid_exact_sui_payload_value_mismatch`,
   `invalid_exact_sui_payload_recipient_mismatch`,
   `invalid_exact_sui_payload_already_executed`; or
2. **Generalise the existing ones** by dropping `evm` from the names, since the
   underlying conditions (bad signature, value mismatch, recipient mismatch) are
   not EVM-specific at all.

(2) seems preferable: the same four failure modes recur in every scheme
implementation, and the current names force each new chain to either invent
codes or lose fidelity.
