terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  alias  = "primary_region"
  default_tags {
    tags = {
      Environment = "Primary-Region"
      Name        = "Devopscaptain"
    }
  }
}

provider "aws" {
  region = "us-west-2"
  alias  = "secondary_region"
  default_tags {
    tags = {
      Environment = "Secondary-Region"
      Name        = "Devopscaptain"
    }
  }
}