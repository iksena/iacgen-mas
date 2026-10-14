variable "create_eks" {
  type    = bool
  default = false
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = ""
}

variable "cluster_version" {
  description = "Kubernetes `<major>.<minor>` version to use for the EKS cluster (i.e.: `1.27`)"
  type        = string
  default     = null
}

# variable "upgrade_policy" {
#     description = "Choose whether you want the standard or extended upgrade policy. Extended does have an additional cost"
#     type = string
#     default = "STANDARD"
# }

variable "authentication_mode" {
  description = "The authentication mode for the cluster. Valid values are `CONFIG_MAP`, `API` or `API_AND_CONFIG_MAP`"
  type        = string
  default     = "API_AND_CONFIG_MAP"
}

variable "control_plane_subnet_ids" {
  description = "A list of subnet IDs where the EKS cluster control plane (ENIs) will be provisioned. Used for expanding the pool of subnets used by nodes/node groups without replacing the EKS control plane"
  type        = list(string)
  default     = []
}

variable "subnet_ids" {
  description = "A list of subnet IDs where the nodes/node groups will be provisioned. If `control_plane_subnet_ids` is not provided, the EKS cluster control plane (ENIs) will be provisioned in these subnets"
  type        = list(string)
  default     = []
}

# variable "cluster_endpoint_private_access" {
#   description = "Indicates whether or not the Amazon EKS private API server endpoint is enabled"
#   type        = bool
#   default     = true
# }

# variable "cluster_endpoint_public_access" {
#   description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled"
#   type        = bool
#   default     = false
# }

# variable "cluster_endpoint_public_access_cidrs" {
#   description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint"
#   type        = list(string)
#   default     = ["0.0.0.0/0"]
# }

# variable "cluster_encryption_config" {
#   description = "Configuration block with encryption configuration for the cluster. To disable secret encryption, set this value to `{}`"
#   type        = any
#   default = {
#     resources = ["secrets"]
#   }
# }

# variable "attach_cluster_encryption_policy" {
#   description = "Indicates whether or not to attach an additional policy for the cluster IAM role to utilize the encryption key provided"
#   type        = bool
#   default     = true
# }

# variable "cluster_tags" {
#   description = "A map of additional tags to add to the cluster"
#   type        = map(string)
#   default     = {}
# }

# variable "create_cluster_primary_security_group_tags" {
#   description = "Indicates whether or not to tag the cluster's primary security group. This security group is created by the EKS service, not the module, and therefore tagging is handled after cluster creation"
#   type        = bool
#   default     = true
# }

# variable "enable_cluster_creator_admin_permissions" {
#   description = "Indicates whether or not to add the cluster creator (the identity used by Terraform) as an administrator via access entry"
#   type        = bool
#   default     = true
# }