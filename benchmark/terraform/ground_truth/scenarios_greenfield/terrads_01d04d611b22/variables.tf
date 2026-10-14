variable "aws_region" {
  description = "value of the region to deploy the resources"
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "value of the profile to use"
  default     = "default"
}

variable "vpc_ip4_cidr_block" {
  description = "value of the IP4 cidr block for the vpc"
  default     = "10.16.0.0/16"
  validation {
    condition     = can(regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$", var.vpc_ip4_cidr_block))
    error_message = "value of the IP4 cidr block for the vpc must be a valid CIDR block"
  }
}

variable "is_ipv6_enabled" {
  description = "enables ipv6 for vpc and subnets"
  default     = true
  validation {
    condition     = can(regex("^(true|false)$", var.is_ipv6_enabled))
    error_message = "value of the is_ipv6_enabled must be a boolean"
  }
}

variable "ipv4_subnets_new_bits" {
  description = "value of the new bits for the ipv4 subnets"
  default     = 4 # 16 subnets /20
  validation {
    condition     = can(regex("^\\d+$", var.ipv4_subnets_new_bits))
    error_message = "value of the new bits for the ipv4 subnets must be a number"
  }
}

variable "ipv6_subnets_new_bits" {
  description = "value of the new bits for the ipv4 subnets"
  default     = 8 # min /64
  validation {
    condition     = can(regex("^\\d+$", var.ipv6_subnets_new_bits))
    error_message = "value of the new bits for the ipv6 subnets must be a number"
  }
}

variable "sn_details" {
  description = "values of the subnets details for the vpc"
  type = list(object({
    name              = string
    availability_zone = string
    is_public         = bool
  }))
  validation {
    condition     = length(var.sn_details) > 0
    error_message = "value of the subnets details for the vpc must be a list with at least one element"
  }
  default = [
    {
      name              = "sn-reserved-A-private"
      availability_zone = "us-east-1a"
      is_public         = false
    },
    {
      name              = "sn-db-A-private"
      availability_zone = "us-east-1a"
      is_public         = false
    },
    {
      name              = "sn-app-A-private"
      availability_zone = "us-east-1a"
      is_public         = false
    },
    {
      name              = "sn-web-A-public"
      availability_zone = "us-east-1a"
      is_public         = true
    },
    {
      name              = "sn-reserved-B-private"
      availability_zone = "us-east-1b"
      is_public         = false
    },
    {
      name              = "sn-db-B-private"
      availability_zone = "us-east-1b"
      is_public         = false
    },
    {
      name              = "sn-app-B-private"
      availability_zone = "us-east-1b"
      is_public         = false
    },
    {
      name              = "sn-web-B-public"
      availability_zone = "us-east-1b"
      is_public         = true
    },
    {
      name              = "sn-reserved-C-private"
      availability_zone = "us-east-1c"
      is_public         = false
    },
    {
      name              = "sn-db-C-private"
      availability_zone = "us-east-1c"
      is_public         = false
    },
    {
      name              = "sn-app-C-private"
      availability_zone = "us-east-1c"
      is_public         = false
    },
    {
      name              = "sn-web-C-public"
      availability_zone = "us-east-1c"
      is_public         = true
    }
  ]

}

variable "instance_tenancy" {
  description = "value of the instance tenancy for the vpc"
  default     = "default"
}

variable "enable_dns_hostnames" {
  description = "value of the enable dns hostnames for the vpc"
  default     = true
  validation {
    condition     = can(regex("^(true|false)$", var.enable_dns_hostnames))
    error_message = "value of the enable dns hostnames for the vpc must be a boolean"
  }
}

variable "enable_dns_support" {
  description = "value of the enable dns support for the vpc"
  default     = true
  validation {
    condition     = can(regex("^(true|false)$", var.enable_dns_support))
    error_message = "value of the enable dns support for the vpc must be a boolean"
  }
}

variable "environment" {
  description = "value of the environment"
  default     = "dev"
}
