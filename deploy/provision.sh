#!/usr/bin/env bash
#
# Provision a single small GCP VM to host the x402 demo.
#
# Creates: a static external IP, a VM with Docker, and firewall rules for
# 80/443 plus SSH restricted to Google's IAP forwarders. Prints the DNS record
# you need to add.
#
# This script is idempotent — re-running it will not duplicate resources.
#
# Usage:
#   PROJECT=my-project DOMAIN=x402.example.com ./provision.sh
#
# Nothing here is destructive, but it DOES create billable resources. e2-micro
# in us-west1/us-central1/us-east1 is free-tier eligible; the static IP is free
# while attached to a running instance.

set -euo pipefail

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
DOMAIN="${DOMAIN:?set DOMAIN, e.g. DOMAIN=x402.example.com}"
# Free-tier eligible regions are us-west1, us-central1, us-east1 only.
ZONE="${ZONE:-us-central1-a}"
REGION="${ZONE%-*}"
NAME="${NAME:-x402-demo}"
# e2-micro (1GB) cannot compile this dependency tree — it OOMs partway through
# the Rust build even with swap. e2-medium builds it comfortably; downsize
# afterwards if the running footprint justifies it.
MACHINE="${MACHINE:-e2-medium}"

if [[ -z "$PROJECT" ]]; then
  echo "!! No GCP project set. Pass PROJECT=... or run: gcloud config set project <id>" >&2
  exit 1
fi

echo "==> Project $PROJECT / zone $ZONE / $MACHINE / domain $DOMAIN"

exists() { "$@" >/dev/null 2>&1; }

# --- Static IP -------------------------------------------------------------
# Reserved separately from the VM so the address survives rebuilding the
# instance — otherwise every recreate means another DNS change and another
# wait for propagation.
if exists gcloud compute addresses describe "$NAME-ip" --region "$REGION" --project "$PROJECT"; then
  echo "==> Static IP $NAME-ip already exists"
else
  echo "==> Reserving static IP"
  gcloud compute addresses create "$NAME-ip" --region "$REGION" --project "$PROJECT"
fi
IP=$(gcloud compute addresses describe "$NAME-ip" --region "$REGION" --project "$PROJECT" --format='value(address)')

# --- Firewall --------------------------------------------------------------
# Only 80 and 443. Envoy's :10000 and the verifier's :50051 stay unreachable
# from outside, so the gate cannot be bypassed by hitting the VM directly.
if exists gcloud compute firewall-rules describe "$NAME-web" --project "$PROJECT"; then
  echo "==> Firewall rule $NAME-web already exists"
else
  echo "==> Creating firewall rule (80/443)"
  gcloud compute firewall-rules create "$NAME-web" \
    --project "$PROJECT" \
    --allow tcp:80,tcp:443 \
    --target-tags "$NAME" \
    --description "x402 demo: HTTP for ACME challenge, HTTPS for traffic"
fi

# SSH is NOT open to the internet. Google's Identity-Aware Proxy forwards from
# this range only, and it authenticates and audits the connection before it
# reaches the VM — so there is nothing on 22 to scan or brute-force, and access
# follows the IAM identity rather than an authorized_keys file.
#
#   gcloud compute ssh "$NAME" --zone "$ZONE" --tunnel-through-iap
if exists gcloud compute firewall-rules describe "$NAME-ssh-iap" --project "$PROJECT"; then
  echo "==> Firewall rule $NAME-ssh-iap already exists"
else
  echo "==> Creating firewall rule (SSH from IAP only)"
  gcloud compute firewall-rules create "$NAME-ssh-iap" \
    --project "$PROJECT" \
    --allow tcp:22 \
    --source-ranges 35.235.240.0/20 \
    --target-tags "$NAME" \
    --description "x402 demo: SSH via Identity-Aware Proxy only, never the internet"
fi

# OS Login ties SSH to the Google identity and IAM role, so access is granted
# and revoked centrally instead of by editing authorized_keys on the box.
echo "==> Enabling OS Login project-wide"
gcloud compute project-info add-metadata --project "$PROJECT" \
  --metadata enable-oslogin=TRUE >/dev/null

# --- VM --------------------------------------------------------------------
if exists gcloud compute instances describe "$NAME" --zone "$ZONE" --project "$PROJECT"; then
  echo "==> Instance $NAME already exists"
else
  echo "==> Creating $MACHINE instance"
  gcloud compute instances create "$NAME" \
    --project "$PROJECT" \
    --zone "$ZONE" \
    --machine-type "$MACHINE" \
    --image-family debian-12 \
    --image-project debian-cloud \
    --boot-disk-size 20GB \
    --boot-disk-type pd-standard \
    --address "$IP" \
    --tags "$NAME" \
    --scopes logging-write,monitoring-write \
    --metadata-from-file startup-script=<(cat <<'STARTUP'
#!/bin/bash
set -eux
# Docker CE from the official repo; Debian's packaged docker.io lags badly.
apt-get update
apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# An e2-micro has 1GB of RAM. Compiling the Rust binary will OOM without swap.
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
STARTUP
)
fi

cat <<EOF

==> Provisioned.

    Static IP: $IP

NEXT STEPS

1. Point DNS at it — create an A record and wait for it to resolve:

       $DOMAIN.  A  $IP

   Verify before continuing, or Caddy's certificate request will fail and
   Let's Encrypt will rate-limit repeated attempts:

       dig +short $DOMAIN

2. SSH in and deploy:

       gcloud compute ssh $NAME --zone $ZONE --project $PROJECT

       sudo usermod -aG docker \$USER && exec newgrp docker
       git clone https://github.com/0xfreak0/sui-x402-verifier.git
       cd sui-x402-verifier/deploy
       cp .env.example .env
       \$EDITOR .env          # set X402_DOMAIN, ACME_EMAIL, X402_PAY_TO, secret
       docker compose up -d --build

3. Confirm it works:

       curl -i -X POST https://$DOMAIN/graphql \\
         -H 'Content-Type: application/json' \\
         -d '{"query":"{ chainIdentifier }"}'

   Demo page: https://$DOMAIN/demo/

EOF
