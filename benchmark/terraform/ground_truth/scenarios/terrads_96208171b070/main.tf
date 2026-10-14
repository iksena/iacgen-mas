terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

resource "aws_organizations_organization" "org" {
  feature_set          = var.feature_set
  enabled_policy_types = var.enabled_policy_types
}
