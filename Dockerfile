# syntax=docker/dockerfile:1.7

# Builder stage — compile the binary with cache mounts for registry/git
# and target/. The binary is copied out of the cache-mounted target/
# before the layer is finalized; the cached dirs are not part of the
# final image.
FROM rust:1-bookworm AS builder

WORKDIR /app

# Manifests first — Cargo.toml declares a `[[bench]]` target, so
# benches/ must exist for manifest parsing even when we build only the
# binary.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --bin dnsink \
 && cp /app/target/release/dnsink /app/dnsink

# Runtime stage — distroless/cc for glibc-compatible dynamic linking
# without a shell or package manager. :nonroot pins UID 65532.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# OCI labels — `org.opencontainers.image.source` is what GHCR uses to
# auto-link the package to the repo page.
LABEL org.opencontainers.image.source="https://github.com/kakarot-dev/dnsink"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description="High-performance DNS proxy with threat-feed blocking, entropy-based tunneling detection, and Prometheus metrics"

COPY --from=builder /app/dnsink /dnsink
COPY config.docker.toml /etc/dnsink/config.toml

USER nonroot:nonroot

# 5353 reflects what the baked config actually binds. Map to host 53
# at run time: `-p 53:5353/udp -p 53:5353/tcp`.
EXPOSE 5353/udp 5353/tcp 9090/tcp

ENTRYPOINT ["/dnsink", "--config", "/etc/dnsink/config.toml"]
