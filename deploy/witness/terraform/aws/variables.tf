variable "region" {
  type        = string
  description = "AWS region to run the witness in (part of the fleet's jurisdiction/infra spread)."
  default     = "us-west-2"
}

variable "ami_id" {
  type        = string
  description = "Base AMI with Docker (e.g. a recent Amazon Linux 2023 image)."
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "image_repository" {
  type    = string
  default = "ghcr.io/auths-dev/auths-witness-node"
}

variable "image_tag" {
  type    = string
  default = "0.1.16"
}

variable "image_digest" {
  type        = string
  description = "Pinned image digest (sha256:...). Takes precedence over image_tag; set it in production."
  default     = ""
}

variable "roles" {
  type    = list(string)
  default = ["kel", "cosign", "anchor"]
}

variable "port" {
  type    = number
  default = 3333
}

variable "allowed_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to reach the witness HTTP surface."
  default     = ["0.0.0.0/0"]
}

variable "witness_seed" {
  type        = string
  description = "32-byte hex first-boot seed. Source from a secret store, not version control."
  sensitive   = true
}

variable "witness_name" {
  type        = string
  description = "The witness's public name, carried in its cosignatures and checkpoints."
}

variable "registry_url" {
  type        = string
  description = "The parties' public identity registry to sync refs/auths/* from (a peer witness, or the first-party network.auths.dev). Used by the boot-time sync-registry step."
  default     = "https://network.auths.dev"
}
