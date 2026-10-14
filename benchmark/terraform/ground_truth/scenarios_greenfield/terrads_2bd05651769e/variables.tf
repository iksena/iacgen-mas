#----------------------------------------------#
# network-base: variables                      #
# ./modules/aws/network-base/variables.tf      #
#----------------------------------------------#


variable "cidr_range" {
  description = "cidr range for vpc"
  type        = string
  default     = "172.69.0.0/16"
}

variable "vpc_tag" {
  description = "vpc tag name"
  type        = string
  default     = "vpc_name"
}

# PUBLIC SUBNET
variable "pub_sub_cidr" {
  description = "public subnet cidr range"
  type        = string
  default     = "172.69.1.0/24"
}

variable "pub_sub_tag" {
  description = "public subnet tag name"
  type        = string
  default     = "public_subnet"
}


# PRVATE SUBNETS
variable "priv_sub_cidr" {
  description = "private subnet cidr range"
  type        = string
  default     = "172.69.2.0/24"
}

variable "priv_sub_tag" {
  description = "private subnet tag name"
  type        = string
  default     = "private_subnet"
}


# INTERNET GATEWAY
variable "igw_tag" {
  description = "internet gateway tag"
  type        = string
  default     = "igw_tag"
}

variable "public_rules" {
  type = list(object({
    port        = number
    porto       = string
    cidr_blocks = list(string)
  }))
  default = [
    {
      port        = 80
      porto       = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      port        = 22
      porto       = "tcp"
      cidr_blocks = ["172.69.0.0/16"]
    }
    # {
    #     port = 3689
    #     porto = "tcp"
    #     cidr_blocks = [""]
    # }
  ]
}

variable "sg_apache_tag" {
  description = "security group tag for WebServer"
  type        = string
  default     = "web-server_security_group"
}

variable "sg_rds_tag" {
  description = "security group for RDS Database"
  type        = string
  default     = "rds_security_group"
}

#--- Route Table
variable "rtb_tag" {
  description = "route table rag"
  type        = string
  default     = "rtb_tag"
}