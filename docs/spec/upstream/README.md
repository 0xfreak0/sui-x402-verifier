# Vendored x402 specification

Verbatim copies of the upstream spec, kept in-tree so conformance is checkable
against a fixed target and so drift is visible in a diff rather than discovered
at runtime.

| File | Upstream path |
|---|---|
| `x402-specification-v2.md` | `specs/x402-specification-v2.md` |
| `transport-http-v2.md` | `specs/transports-v2/http.md` |
| `scheme_exact.md` | `specs/schemes/exact/scheme_exact.md` |
| `scheme_exact_sui.md` | `specs/schemes/exact/scheme_exact_sui.md` |

- **Source:** https://github.com/x402-foundation/x402
- **Commit:** `34cb6bd04c88f4333f56b9c778d3d35df997379c` (`main` at time of vendoring)
- **Vendored:** 2026-08-05

The spec now lives under the x402 Foundation. It was previously vendored from
`coinbase/x402` @ `dd927a26`; `scheme_exact_sui.md` is byte-identical between
the two, so the conformance work in `../../sui-scheme-conformance.md` carries
over unchanged. The other three files gained content — new per-network rules
(TON, Starknet) in `scheme_exact.md`, and a clarification in the HTTP transport
that `PAYMENT-REQUIRED` is the canonical location for the `PaymentRequired`
object — none of which alters anything this implementation relies on.

## Refreshing

```bash
gh api repos/x402-foundation/x402/contents/specs/x402-specification-v2.md --jq '.content' | base64 -d > x402-specification-v2.md
gh api repos/x402-foundation/x402/contents/specs/transports-v2/http.md      --jq '.content' | base64 -d > transport-http-v2.md
gh api repos/x402-foundation/x402/contents/specs/schemes/exact/scheme_exact.md     --jq '.content' | base64 -d > scheme_exact.md
gh api repos/x402-foundation/x402/contents/specs/schemes/exact/scheme_exact_sui.md --jq '.content' | base64 -d > scheme_exact_sui.md
```

Update the commit SHA above when you do. The JSON examples in these files are
extracted into test fixtures (`tests/fixtures/`), so a spec change that alters a
shape will fail the test suite rather than pass silently.

## Note on an earlier design assumption

`scheme_exact_sui.md` §Appendix "Future Work" lists Sui **Address Balances** —
gasless stablecoin transfers with no coin-object selection — as *in
development*.

**That is out of date, and this note used to repeat it.** Address Balances has
shipped on testnet and mainnet, gasless settlement works, and it is what this
implementation does by default. Measured at `computation_cost: 0,
storage_cost: 0` with the payer holding no SUI. See
`../../sui-scheme-conformance.md` for the three conditions that apply and are
nowhere in the spec text.

The vendored file is kept verbatim, stale appendix included, because the point
of vendoring is to diff against what upstream actually says.
