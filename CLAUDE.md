# sui-x402-verifier

An Envoy filter that puts the [x402](https://github.com/coinbase/x402) payment
protocol in front of arbitrary upstreams, settling on Sui. Anonymous callers get
a metered free tier; a settled payment buys a session with its own quota and
lifetime. Per-route policies price different upstreams differently and can
credit different wallets.

`ext_proc` is the default filter because it can settle on the **response** path,
which is what the Sui scheme's ordering requires: verify → serve → settle.
`ext_authz` is kept as a fallback and settles early; that difference is
documented, not accidental.

## Working notes go in `scratchpad/`

`scratchpad/` is gitignored. Put development artifacts there rather than in the
repo root or `docs/`:

- Session notes and progress logs
- Design spikes, half-finished analysis, parked work
- Runbooks that name real hosts, wallets, ports, or GCP projects
- Anything carrying a wallet address, secret, or machine-specific path

**Do not create `*-NOTES.md`, `TODO.md`, `PLAN.md`, or similar at the repo
root.** They get committed by accident and then have to be defended in review.

`docs/` and `README.md` are the opposite: written for an outside reader,
reviewed, and expected to stay true. If a scratchpad note starts getting cited
in conversation, that is the signal to rewrite it for that audience and promote
it — not to leave it in two places.

## Never commit a wallet address

Not a real one, not a placeholder that looks real, not "just for testing".
Receiving wallets come from the environment:

- `X402_PAY_TO` — the default payee
- `X402_PAY_TO_<POLICY>` — per-policy payee, e.g. `X402_PAY_TO_GRPC`
- `X402_SESSION_HMAC_SECRET` — session signing key
- `X402_SUI_PRIVATE_KEY` — client signing key, used only by `x402-pay` and
  `x402-demo`

Committed configs carry the zero address, and `Config::validate` **refuses to
start** on it, so a missing variable fails loudly at boot instead of quietly
settling somewhere wrong. Test fixtures use obviously-fake repeated-digit
addresses (`0x1111…`).

Tracked config: `config.example.yaml` and `config.demo.yaml`. Every other
`config.*.yaml` is gitignored.

## Custody

The verifier holds **no keys**. It verifies signatures and relays transactions
the client already signed — broadcasting needs no private key, and this is what
lets the gateway charge you without being able to steal from you. `/supported`
advertises `"signers": {}`, and that must stay true.

`src/bin/x402-demo.rs` is the one exception: it holds a hot testnet wallet so
visitors can try the flow without one. It is demo scaffolding, not part of the
product, and its spend controls are not optional.

## Tests

Test-first. Every behavioural claim in `docs/` should be backed by a named test,
and security properties especially: the bypasses that were found during
development each have a regression test, and they are the reason those tests
read like accusations (`ipv6_clients_cannot_reset_the_free_tier_by_rotating_addresses`).

Name tests after the property, not the function. Redis-backed tests no-op
without `X402_TEST_REDIS_URL` rather than failing.

```sh
cargo test
cargo clippy --all-targets
```

## Comments

Comment the non-obvious: why a choice was made, what breaks without it, what a
reader would otherwise get wrong. Several comments in this codebase exist
because the alternative was tried and produced a subtle bug — the read-mask
asymmetry between `SimulateTransaction` and `ExecuteTransaction`, the
`OverwriteIfExistsOrAdd` header action, the `/64` IPv6 bucket. Do not delete
that kind of comment to tidy up.

Do not narrate what the code already says.

## Running the stack locally

Three processes plus Envoy. See `scratchpad/deploy-runbook.md` for the exact
commands and current environment.

```
browser ─▶ x402-demo :8402 ─▶ envoy :10000 ─▶ upstream
                                  │
                                  └─ext_proc─▶ x402-verifier :50051
                                               metrics :9090
                                               facilitator API :50052
```
