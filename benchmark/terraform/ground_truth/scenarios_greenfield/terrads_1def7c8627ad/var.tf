#provider
variable "aws_region" {
  type        = string 
  description = "region"
  default     = "eu-central-1"
}
# vpc cidr
variable "cidr_vpc" {
  type        = string 
  description = "cidr"
  default     = "10.0.0.0/16" 
}
# pubsub-1
variable "subpub1" {
  type        = string 
  description = "subnet"
  default     = "10.0.1.0/24" 
}
# pubsub-2
variable "subpub2" {
  type        = string 
  description = "subnet"
  default     = "10.0.2.0/24" 
}
# pvtsub-1
variable "subpvt1" {
  type        = string 
  description = "subnet"
  default     = "10.0.3.0/24" 
}
# pvtsub-2
variable "subpvt2" {
  type        = string 
  description = "subnet"
  default     = "10.0.4.0/24" 
}
# azpub-1
variable "azpub1" {
  type        = string 
  description = "subnet"
  default     = "eu-central-1a" 
}
# azpub-2
variable "az_sub_pub2" {
  type        = string 
  description = "subnet"
  default     = "eu-central-1b" 
}
# azpvt-1
variable "az_sub_pvt1" {
  type        = string 
  description = "subnet"
  default     = "eu-central-1a" 
}
# azpvt-2
variable "az_sub_pvt2" {
  type        = string 
  description = "subnet"
  default     = "eu-central-1b"
}
