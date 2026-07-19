# terraform/gcp — witness on Cloud Run

Runs the same `ghcr.io/auths-dev/auths-witness-node` image as a Cloud Run
service, with the anchor store on a mounted persistent disk (single-writer;
Cloud Run min/max instances pinned to 1 so the CAS store never fans out).

Core variables mirror `../aws`: `image_digest`, `roles`, `port`, and
`witness_seed` (sourced from Secret Manager, never version control). A `main.tf`
using `google_cloud_run_v2_service` with the seed wired from
`google_secret_manager_secret_version` is the intended shape; it is kept minimal
here so the fleet's own IaC (in `auths-witness-cloud/deploy`) composes it.
