variable "primary_bucket_name" {
  type        = string
  default = "example1"
  description = "primary bucket name to be created for multi_region_access_point"
}

variable "secondary_bucket_name" {
  type        = string
  default = "example2"
  description = "secondary bucket name to be created for multi_region_access_point"
}

variable "access_point_name" {
  type    = string
  default = "example-mrap"
  description = "Name for multi_region_access_point"
}