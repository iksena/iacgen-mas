
variable "project" {
  default     = "demo"
  type        = string
  description = "Name of project this VPC is meant to house"
}

variable "environment" {
  default     = "poc"
  type        = string
  description = "Name of environment this VPC is targeting"
}

variable "name" {
  default     = "demo-dataflow"
  type        = string
  description = "Name of the VPC"
}

variable "region" {
  default     = "us-west-2"
  type        = string
  description = "Region of the VPC"
}

variable "availability_zones" {
  default     = ["us-west-2a", "us-west-2b"]
  type        = list
  description = "List of availability zones"
}

variable "key_name" {
  default     = "kplinuxdemo"
  type        = string
  description = "EC2 Key pair name for the bastion"
}

variable "cidr_block" {
  default     = "10.0.0.0/16"
  type        = string
  description = "CIDR block for the VPC"
}

variable "public_subnet_cidr_blocks" {
  default     = ["10.0.0.0/24", "10.0.2.0/24"]
  type        = list
  description = "List of public subnet CIDR blocks"
}

variable "private_subnet_cidr_blocks" {
  default     = ["10.0.1.0/24", "10.0.3.0/24"]
  type        = list
  description = "List of private subnet CIDR blocks"
}

variable "aws_internet_gateway" {
  default     = "igwdemo"
  type        = string
  description = "Region of the VPC"
}

variable "bastion_ami" {
  default     = " ami-0d6621c01e8c2de2c"
  type        = string
  description = "Bastion Amazon Machine Image (AMI) ID"
}

variable "bastion_ebs_optimized" {
  default     = false
  type        = bool
  description = "If true, the bastion instance will be EBS-optimized"
}

variable "bastion_instance_type" {
  default     = "t3.nano"
  type        = string
  description = "Instance type for bastion instance"
}

variable "tags" {
  default     = {}
  type        = map(string)
  description = "Extra tags to attach to the VPC resources"
}
