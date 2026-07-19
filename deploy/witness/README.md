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

## Quickstart (Compose)

```bash
cd deploy/witness
WITNESS_SEED=$(openssl rand -hex 32) docker compose up
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
