# Slim, hardened image for the auths-witness rct server.
#
# Build stage: static musl build so the runtime image needs no libc/runtime.
# Runtime stage: distroless-static, non-root, read-only rootfs (set at `docker run`
# / compose / k8s level — see README). The signing key is INJECTED at runtime
# (secret/volume or AUTHS_WITNESS_SEED), never baked into the image.

FROM rust:1.93 AS build
ARG TARGETARCH
WORKDIR /src
# Install musl tooling and the static target for THIS build's architecture.
# Resolving the Rust triple from the Docker TARGETARCH keeps a single image
# definition correct on both amd64 and arm64 build hosts (no emulated cross).
RUN case "$TARGETARCH" in \
        amd64) echo x86_64-unknown-linux-musl ;; \
        arm64) echo aarch64-unknown-linux-musl ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac > /rust-target \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
# Copy the source (including rust-toolchain.toml) FIRST, then add the static
# target to the toolchain the toolchain file actually selects — adding it to a
# different toolchain instance before the copy leaves the build without a musl
# std for the active toolchain (E0463: can't find crate for `core`).
COPY . .
RUN rustup target add "$(cat /rust-target)"
# Build only the slim witness binary; auths-core `default = []` keeps the
# keychain / ssh-agent / pairing surface out of the dependency tree.
RUN cargo build --release --locked \
    --target "$(cat /rust-target)" \
    -p auths-witness --bin auths-witness \
    && cp "target/$(cat /rust-target)/release/auths-witness" /auths-witness

FROM gcr.io/distroless/static-debian12:nonroot
# Non-root (the distroless `nonroot` user is uid 65532).
USER nonroot:nonroot
COPY --from=build /auths-witness /usr/local/bin/auths-witness

# Receipts DB + keystore live under a writable volume mounted at /data; the rest
# of the rootfs is read-only (enforce with `--read-only` / k8s readOnlyRootFilesystem).
VOLUME ["/data"]
EXPOSE 3333

# TLS terminates at a reverse proxy; bind plaintext on the pod/host network only.
ENTRYPOINT ["/usr/local/bin/auths-witness"]
CMD ["--bind", "0.0.0.0:3333", "--identity", "/data/witness.key", "--persist", "/data/receipts.db"]
