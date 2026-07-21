# One Auths witness node on AWS (EC2 + Docker). The same module Auths runs for
# its own us-* quorum members; pin `image_digest` for a reproducible node.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_security_group" "witness" {
  name_prefix = "auths-witness-"
  description = "Auths witness node: inbound witness HTTP only"

  ingress {
    description = "witness HTTP"
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "witness" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.witness.id]

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    image        = var.image_digest != "" ? "${var.image_repository}@${var.image_digest}" : "${var.image_repository}:${var.image_tag}"
    roles        = join(",", var.roles)
    port         = var.port
    witness_seed = var.witness_seed
    witness_name = var.witness_name
    registry_url = var.registry_url
  })

  tags = {
    Name    = "auths-witness"
    Project = "auths-witness-network"
  }
}
