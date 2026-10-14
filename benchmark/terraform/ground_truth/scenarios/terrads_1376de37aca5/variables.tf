# General Settings
variable "namespace" {
  type        = string
  default     = ""
  description = "Namespace, which could be your organization name or abbreviation, e.g. 'eg' or 'cp'"
}

variable "environment" {
  type        = string
  default     = ""
  description = "Environment, e.g. 'prod', 'staging', 'dev', 'pre-prod', 'UAT'"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags (e.g. `map('BusinessUnit','XYZ')`"
}

variable "attributes" {
  type        = list(string)
  default     = []
  description = "Additional attributes (e.g. `1`)"
}

# Assumed Role
variable "admin_name" {
  type        = string
  default     = "admin"
  description = "Name for the admin group and role (e.g. `admin`)"
}

variable "other_group_name" {
  type        = string
  default     = "other"
  description = "Name for the group with non-admin users"
}

variable "admin_user_names" {
  type        = list(any)
  default     = []
  description = "Optional list of IAM user names to add to the admin group"
}

variable "other_user_names" {
  type        = list(any)
  default     = []
  description = "Optional list of IAM user names to setup"
}
