variable "vpc_cidr" {
  description = "CIDR for the VPC."
  default = "10.16.0.0/16"
}
variable "enable_dns_support" {
  description = "Flag to enable or disable DNS support in the VPC."
  default = true
}
variable "enable_dns_hostnames" {
  description = "Flag to enable or disable DNS hostnames in the VPC."
  default = true
}
variable "web_subnet_count" {
  description = "Number of web (public) subnets required."
  default = 0
}
variable "app_subnet_count" {
  description = "Number of app (private) subnets required."
  default = 0
}
variable "db_subnet_count" {
  description = "Number of DB (private) subnets required."
  default = 0
}
variable "reserved_subnet_count" {
  description = "Number of reserved (for future use) subnets required."
  default = 0
}
variable "web_cidr_blocks" {
  description = "CIDR blocks for the web subnets. Example [for i in range(0, 4, 1) : cidrsubnet(\"10.16.0.0/16\", 4, i)]"
  default = []
}
variable "app_cidr_blocks" {
  description = "CIDR blocks for the app subnets. Example [for i in range(4, 8, 1) : cidrsubnet(\"10.16.0.0/16\", 4, i)]"
  default = []
}
variable "db_cidr_blocks" {
  description = "CIDR blocks for the DB subnets. Example [for i in range(8, 12, 1) : cidrsubnet(\"10.16.0.0/16\", 4, i)]"
  default = []
}
variable "reserved_cidr_blocks" {
  description = "CIDR blocks for the reserved subnets. Example [for i in range(12, 16, 1) : cidrsubnet(\"10.16.0.0/16\", 4, i)]"
  default = []
}
variable "max_subnetcount" {
  description = "Maximum number of subnets in the VPC."
  default = 20
}
variable "vpc_endpoints" {
  description = "Map for building Interface endpoints."
  default = {}
}
variable "security_group_ids" {
  description = "Security group IDs for the Interface endpoints."
  default = []
}
variable "availability_zone" {
  description = "AZs where the Subnets are created."
  default = []
}
variable "service_name" {
  description = "Service name for the Gateway endpoint. Example com.amazonaws.us-east-1.s3"
  default = ""
}
variable "vpc_endpoint_type" {
  description = "Endpoint type for the Gateway endpoint."
  default = "Gateway"
}
variable "subnet_ids" {
  description = "Subnets IDS where the Interface endpoints should be provisioned."
  default = []
}
variable "vpc_name" {
  description = "Name prefix for the VPC."
  default = "tf-project"
}