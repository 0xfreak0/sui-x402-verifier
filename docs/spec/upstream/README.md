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

- **Source:** https://github.com/coinbase/x402
- **Commit:** `dd927a26cfefc98c24b3ec38b3a8f204dad0c60d` (`main` at time of vendoring)
- **Vendored:** 2026-08-04

## Refreshing

```bash
gh api repos/coinbase/x402/contents/specs/x402-specification-v2.md --jq '.content' | base64 -d > x402-specification-v2.md
gh api repos/coinbase/x402/contents/specs/transports-v2/http.md      --jq '.content' | base64 -d > transport-http-v2.md
gh api repos/coinbase/x402/contents/specs/schemes/exact/scheme_exact.md     --jq '.content' | base64 -d > scheme_exact.md
gh api repos/coinbase/x402/contents/specs/schemes/exact/scheme_exact_sui.md --jq '.content' | base64 -d > scheme_exact_sui.md
```

Update the commit SHA above when you do. The JSON examples in these files are
extracted into test fixtures (`tests/fixtures/`), so a spec change that alters a
shape will fail the test suite rather than pass silently.

## Note on an earlier design assumption

`scheme_exact_sui.md` §Appendix "Future Work" lists Sui **Address Balances** —
gasless stablecoin transfers with no coin-object selection — as *in development*,
not current. An earlier design document for this project assumed that feature
shipped and concluded settlement would be free for everyone. It is not: the
current scheme requires a fully-formed signed transaction where either the
client pays gas, or the facilitator sponsors it through the interactive gas
station protocol.
