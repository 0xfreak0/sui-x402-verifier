# Security

This is an exploratory prototype. It is unaudited, has only ever been run
against Sui testnet, and carries no security guarantees.

## Reporting something

Open a GitHub issue. Public reporting is fine here: there is no deployed user
base to protect and nothing in this repository holds funds.

If you would rather not open a public issue, use GitHub's private vulnerability
reporting on this repository.

## What is in scope

The parts where a bug would actually matter to someone reading this as a
reference:

- Bypasses of the payment gate — reaching a gated upstream without a valid
  payment or session
- Forging or extending a session token
- Replaying a payment to mint more than one session
- Free-tier evasion beyond what is documented in the Limitations section
- Anything that would let this service move funds it should not be able to
  move. It holds no keys, and `GET /supported` reporting an empty `signers` map
  is the claim to check that against

## What is out of scope

- `src/bin/x402-demo.rs` holds a hot testnet wallet on purpose, so a visitor can
  try the flow without one. Its funds are worthless testnet USDC and its spend
  controls are documented in the file
- Deployment configuration in `deploy/`, which is an example
- The `ext_authz` filter, which is implemented and unit-tested but not enabled
  in the shipped `envoy.yaml` and not exercised end to end

## Known and documented

Several sharp edges are already written up. Check these before reporting:

- [`docs/settlement-failure.md`](docs/settlement-failure.md) — what happens when
  settlement fails after the resource was already served
- [`docs/sui-scheme-conformance.md`](docs/sui-scheme-conformance.md) — the
  pay-after-service window, and the input-liveness check that bounds it
- The Limitations section of the README — unmetered streaming, ungated gRPC
  reflection, and off-chain `maxTimeoutSeconds` enforcement
