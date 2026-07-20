# The witness node image. Build from the repo root:
#   docker build -f deploy/witness/Dockerfile -t ghcr.io/auths-dev/auths-witness-node .
# Pin by digest in production; the same image serves compose, Helm, and Terraform.

FROM rust:1.93-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p auths-witness-node --bin witness-node

FROM debian:bookworm-slim
# `git` is the reference implementation the `registry` role shells out to for
# git smart-HTTP (upload-pack). `ca-certificates` lets the in-process git2
# HTTPS sync validate remotes. Both kept minimal; apt lists dropped.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --home /data witness
COPY --from=build /src/target/release/witness-node /usr/local/bin/witness-node
USER witness
VOLUME ["/data"]
EXPOSE 3333
ENTRYPOINT ["/usr/local/bin/witness-node"]
CMD ["serve", "--roles", "anchor,kel,cosign", "--bind", "0.0.0.0:3333", "--data-dir", "/data", "--registry", "/registry", "--witness-name", "witness"]
