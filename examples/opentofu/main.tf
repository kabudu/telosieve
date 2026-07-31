terraform {
  required_version = ">= 1.10.0"
}

variable "message" {
  type = string
}

locals {
  values = {
    "cluster/epoch" = "7"
    "user/message"  = var.message
  }
}

resource "terraform_data" "replica_a" {
  input = { replica = "replica-a", values = local.values }
}

resource "terraform_data" "replica_b" {
  input = { replica = "replica-b", values = local.values }
}

resource "terraform_data" "replica_c" {
  input = { replica = "replica-c", values = local.values }
}
