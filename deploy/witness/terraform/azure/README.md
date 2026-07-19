# terraform/azure — witness on Container Instances

Runs the same `ghcr.io/auths-dev/auths-witness-node` image as an Azure Container
Instance, with the anchor store on an attached Azure File share (single-writer).

Core variables mirror `../aws`: `image_digest`, `roles`, `port`, and
`witness_seed` (sourced from Key Vault, never version control). A `main.tf`
using `azurerm_container_group` with the seed wired from
`azurerm_key_vault_secret` is the intended shape; it is kept minimal here so the
fleet's own IaC composes it.
