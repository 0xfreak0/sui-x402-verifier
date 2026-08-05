# Builds both binaries: the gateway verifier and the demo console backend.
#
# Pinned to a concrete toolchain so a rebuild months from now produces the same
# binary rather than tracking whatever :latest became.
#
# Must match the toolchain the workspace is actually developed on:
# sui-transaction-builder 0.3.2 uses a library feature that was unstable before
# 1.94, and an older image fails with E0658 deep inside a dependency rather
# than anywhere that names the real problem.
FROM rust:1.94-slim-bookworm AS build

WORKDIR /src

# Copy manifests first so the dependency layer caches independently of source
# changes — an edit to src/ then rebuilds in seconds rather than minutes.
#
# Every target needs a stub or cargo refuses to build the manifest: the lib, the
# verifier binary, and the two client binaries.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && echo 'fn main() {}' > src/bin/x402-demo.rs \
    && echo 'fn main() {}' > src/bin/x402-pay.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# cargo skips rebuilding if mtime looks unchanged; touch to force it.
RUN find src -name '*.rs' -exec touch {} + && cargo build --release --locked

# Runtime image.
FROM debian:bookworm-slim AS runtime

# ca-certificates is required — both binaries talk to a Sui fullnode over TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Never run as root. A compromised process should not own the container.
RUN useradd --system --uid 10001 --no-create-home x402
USER 10001

COPY --from=build /src/target/release/x402-verifier /usr/local/bin/x402-verifier
COPY --from=build /src/target/release/x402-demo /usr/local/bin/x402-demo

# No ENTRYPOINT: one image, two services. docker-compose.yml chooses which.
CMD ["/usr/local/bin/x402-verifier", "--config", "/etc/x402/config.yaml"]
