# deploy/witness — run a witness from published code

These are the **same** artifacts Auths uses for its own quorum: a Docker
Compose file, a Helm chart, and Terraform modules per cloud. The IaC is the
product — a regulator or counterparty stands up an identical witness from this
directory with zero Auths dependency (§19.1, §19.3).

Every template pins **one image digest** so "runs anywhere" is tested, not
assumed. The node ships as a static musl binary + container; the binary is
itself witnessed (entered in the Auths transparency log and Rekor) before it
witnesses anything (§19.4).

## One node, three roles

A single artifact runs any combination of three trust roles behind one hardened
HTTP surface (shared body caps, concurrency limits, timeouts):

| Role | What it does |
|---|---|
| `kel` | KEL receipting (the freshness source for key state) |
| `cosign` | Transparency-log checkpoint cosigning |
| `anchor` | Spend-anchor acceptance, duplicity refusal, threshold finalization |

```
witness-node serve --roles kel,cosign,anchor    # default: all three
witness-node serve --roles anchor                # anchor-only witness
```

A role whose required ports lack a working adapter refuses to serve **that
role** at startup with a named error — no half-nodes (I-DEPLOY-6).

### Prefer bare metal?

Install the node binary, then run it directly:

```bash
# From a release: extract witness-node from the v0.1.x tarball onto PATH, or build it:
cargo build --release -p auths-witness-node
# Populate the registry with the parties' public KELs (fetches `refs/auths/*`):
./target/release/witness-node sync-registry --from <party-registry-url> --registry ./registry
./target/release/witness-node serve --roles anchor,kel,cosign \
  --bind 0.0.0.0:3333 --data-dir ./wdata --registry ./registry --witness-name my-w1
```

## Quickstart (Compose)

```bash
cd deploy/witness
# A witness resolves submitter keys against a local copy of the parties' public
# registry. Sync it first (WITNESS_REGISTRY defaults to ./registry) using the
# same image — this fetches the `refs/auths/*` namespace the anchor role reads
# keys from. A plain `git clone` brings only `refs/heads/*`, so the party KELs
# never arrive and every anchor 422s.
WITNESS_REGISTRY=$PWD/registry docker compose run --rm witness \
  sync-registry --from <party-registry-url> --registry /registry
# Re-run the sync to pick up new or rotated parties.
WITNESS_SEED=$(openssl rand -hex 32) WITNESS_REGISTRY=$PWD/registry docker compose up
# health:   http://127.0.0.1:3333/health
# anchors:  POST http://127.0.0.1:3333/v1/anchor
```

## Kubernetes (Helm)

```bash
helm install my-witness ./helm --set image.digest=sha256:<pinned>
```

## Cloud (Terraform)

`terraform/aws`, `terraform/gcp`, and `terraform/azure` each stand up one
witness on that provider. Running the quorum across all three is how a
first-party fleet still spans the diversity floors the verifier checks.

```bash
cd terraform/aws && terraform init && terraform apply -var witness_seed=$WITNESS_SEED
```
