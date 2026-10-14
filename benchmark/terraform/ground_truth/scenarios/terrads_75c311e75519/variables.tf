variable "name" {
  type        = string
  description = "The name of the VPC instance"
  default     = ""
}

variable "internal_cidr" {  
  type        = string
  description = "The cidr range of the internal network for the AWS VPC. Either provide manually or chose from AWS IPAM poolsß"
  default     = "10.0.0.0/16"
}

variable "external_cidr" {
  type        = string
  description = "The cidr range of the external network for the AWS VPC."
  default     = "0.0.0.0/0"
}

variable "provision" {
  type        = bool
  description = "Flag indicating that the instance should be provisioned. If false then an existing instance will be looked up"
  default     = true
}

variable "instance_tenancy" {
  type        = string
  description = "Instance is shared / dedicated, etc. #[default, dedicated, host]"
  default     = "default"
}

variable "name_prefix" {
  type        = string
  description = "Prefix to be added to the names of resources which are being provisioned"
  default     = "swe"
}

variable "enable_dns_support" {
  type        = string
  description = "default is true. [true, false]]"
  default     = true
}

variable "enable_dns_hostnames" {
  type        = string
  description = "Default is true. [true, false]]. ROSA cluster requires this to be set as true"
  default     = true
}

variable "resource_group_name" {
  type        = string
  description = "The name of the resource group where the VPC is deployed. On AWS this value becomes a tag."
  default     = "default"
}