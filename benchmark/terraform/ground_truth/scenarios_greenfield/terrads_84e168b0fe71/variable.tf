

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}


variable "subnet_public_cidrs" {
  type=string
  description = "Public Subnet CIDR values"
  default = "10.0.1.0/24"
  
}

variable "subnet_private_cidrs" {
  type=string
  description = "Private Subnet CIDR values"
  default =  "10.0.2.0/24" 

  
}

variable "availability_zone" {
  description = "Availability Zone for the development environment"
  type        = string
  default     = "us-east-1a"  # Update as needed
}
