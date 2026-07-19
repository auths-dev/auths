# terraform/ — one witness per cloud

Three modules, one shape: stand up a single witness node from the published
image on AWS, GCP, or Azure. Running the quorum across all three is how a
first-party fleet still spans the diversity floors the verifier checks
(`spans_distinct`): distinct providers → distinct infra zones, distinct regions
→ distinct jurisdictions.

- `aws/` — EC2 + Docker (`t4g.small` by default). Complete.
- `gcp/` — Cloud Run service running the same image. See `gcp/README.md`.
- `azure/` — Container Instances running the same image. See `azure/README.md`.

Every module takes the same core variables: `image_digest` (pin it),
`roles`, `port`, and a `witness_seed` sourced from the provider's secret store.
The seed is the node's first-boot identity — generate it once
(`openssl rand -hex 32`) and keep it stable.

## The digest is the contract

Pin `image_digest` in production. The node image is built reproducibly and
entered in the transparency log; pinning the digest is what makes "the IaC is
the product" true — every operator, first- or third-party, runs the identical,
witnessed binary.
