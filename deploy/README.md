# Deploying the demo

One small Linux VM, four containers behind Caddy. Built on the box, so there is
no cross-compilation and no emulation.

```
internet ──▶ caddy :443 ──▶ demo :8402 ──▶ envoy :10000 ──▶ Sui testnet
             (auto TLS)     (page + API)       │            or the demo app
                                               └─ext_proc─▶ verifier :50051
                                                                 │
                                                                 └─▶ redis
```

**Only Caddy publishes ports.** Envoy, the verifier, the demo, `/metrics` and
the facilitator API share a private network namespace and are unreachable from
outside the host regardless of firewall rules. That matters: `/settle` moves
money, and neither `/metrics` nor the facilitator API is authenticated.

## 1. VM

Linux x86-64. Anything with 2 vCPU and 4GB will build comfortably; on 2GB, add
swap first or the Rust build will be killed.

```sh
gcloud compute instances create x402 \
  --machine-type=e2-medium --tags=x402 \
  --image-family=debian-12 --image-project=debian-cloud \
  --address=<reserved static IP>
```

Point the demo's DNS A record at that IP **before** starting the stack — Caddy
requests a certificate on first boot, and a failed ACME challenge is
rate-limited by Let's Encrypt.

## 2. Firewall

Default-deny, then exactly two allows.

```sh
# Caddy. 80 is required for the ACME HTTP-01 challenge.
gcloud compute firewall-rules create x402-https \
  --direction=INGRESS --action=allow --rules=tcp:80,tcp:443 \
  --source-ranges=0.0.0.0/0 --target-tags=x402

# SSH from Google's IAP forwarders only — NOT from the internet.
gcloud compute firewall-rules create x402-ssh-iap \
  --direction=INGRESS --action=allow --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=x402
```

Nothing else. In particular 8402, 9090, 10000, 50051 and 50052 must never be
reachable.

## 3. SSH: OS Login over IAP

Port 22 is closed to the internet; connections tunnel through Google's
Identity-Aware Proxy, which authenticates and audits before anything reaches the
VM. Access is tied to an IAM identity rather than an `authorized_keys` file, so
it can be revoked centrally.

```sh
gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE
gcloud compute ssh x402 --tunnel-through-iap
```

Do not add a public SSH allow "just for setup" — the tunnelled connection works
before any such rule exists.

## 4. Stack

```sh
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git
sudo usermod -aG docker "$USER" && newgrp docker

git clone https://github.com/0xfreak0/sui-x402-verifier.git
cd sui-x402-verifier/deploy

cp .env.example .env && chmod 600 .env
$EDITOR .env          # domain, email, a FRESH HMAC secret, wallet key, payees

docker compose up -d --build
docker compose logs -f
```

First build takes a while — it compiles the whole dependency tree. Subsequent
builds reuse the cached dependency layer.

## 5. Check it

```sh
curl -sI https://$X402_DOMAIN/ | head -1                    # 200, valid cert
curl -s  https://$X402_DOMAIN/policies | jq '.[].name'      # five policies
curl -s -X POST https://$X402_DOMAIN/send \
  -H 'content-type: application/json' -d '{"target":"free"}' | jq '.status, .meter'
```

Then open the page and hit `×10` on the metered GraphQL target: five 200s, then
a 402, then a settlement. If the free meter never counts down, Envoy is not
seeing real client IPs — check `xff_num_trusted_hops` against the number of
proxies actually in front of it.

## Notes

**`../envoy.yaml` runs unmodified.** The verifier, demo and redis share Envoy's
network namespace, so `127.0.0.1:50051`, `:8402` and `:6379` mean the same thing
here as on a laptop. A production copy of `envoy.yaml` differing in a few
addresses would drift from the file the tests exercise.

**Redis rather than the in-memory store.** Sessions and the free tier survive a
restart, so a redeploy does not hand everyone a fresh allowance, and it
exercises the Lua paths the local setup never touches.

**Funding the demo wallet.** Testnet USDC from
[faucet.circle.com](https://faucet.circle.com) (chain: **Sui Testnet**), testnet
SUI from `sui client faucet`. Move the USDC into the wallet's *address balance*
or payments fall back to the coin-object path and start costing gas — see the
funding section in the top-level README.

**The demo holds a hot wallet.** It is the only component with custody of
anything, it is demo scaffolding rather than part of the gateway, and
`X402_MAX_PLAYS` / `X402_PLAYS_PER_IP` are the only thing between a public link
and an empty wallet. Check them before posting the URL.

**Envoy's CA bundle.** `envoy.yaml` points at `/etc/ssl/cert.pem`, which is the
macOS path; the Envoy image is Ubuntu-based and has no such file.
`Dockerfile.envoy` symlinks it so one config works in both places.
