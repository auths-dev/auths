# Slim, hardened image for the murmur-relay store-and-forward mailbox.
#
# Build stage: static musl build so the runtime image needs no libc/runtime.
# Runtime stage: distroless-static, non-root. The relay holds NO secrets and NO
# state on disk (the mailbox + prekey directory are in-memory by design), so there
# is no volume and nothing to inject — it only ever sees an opaque mailbox id and
# opaque ciphertext.
#
# Build context is the AUTHS REPO ROOT (the relay is a workspace crate that pulls
# murmur-core + its deps), so build from there:
#   docker build -f deploy/murmur-relay/Dockerfile -t murmur-relay .
# The repo-root .dockerignore keeps the 165 GB target/ tree out of the context.

FROM rust:1.93 AS build
ARG TARGETARCH
WORKDIR /src
# Resolve the Rust musl triple from the Docker build arch so one Dockerfile is
# correct on both amd64 and arm64 build hosts (no emulated cross). musl-tools
# provides the C toolchain ring's build.rs needs under musl.
RUN case "$TARGETARCH" in \
        amd64) echo x86_64-unknown-linux-musl ;; \
        arm64) echo aarch64-unknown-linux-musl ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust-target \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
# Copy the source (including rust-toolchain.toml) FIRST, then add the static target
# to the toolchain the toolchain file actually selects.
COPY . .
RUN rustup target add "$(cat /rust-target)"
# Build only the relay binary from the workspace. --locked pins Cargo.lock.
RUN cargo build --release --locked \
    --target "$(cat /rust-target)" \
    -p murmur-relay --bin murmur-relay \
    && cp "target/$(cat /rust-target)/release/murmur-relay" /murmur-relay

FROM gcr.io/distroless/static-debian12:nonroot
# Non-root (the distroless `nonroot` user is uid 65532).
USER nonroot:nonroot
COPY --from=build /murmur-relay /usr/local/bin/murmur-relay

# The relay is in-memory and stateless on disk — no VOLUME. TLS terminates at the
# Fly edge (or any reverse proxy); the container binds plaintext on the pod network.
EXPOSE 8080

# Bind all interfaces on the container port (the binary takes the address as a CLI
# arg and reads no env vars). Health is GET / → "murmur-relay <version>".
ENTRYPOINT ["/usr/local/bin/murmur-relay"]
CMD ["serve-http", "0.0.0.0:8080"]
