variable "region" {
  type        = string
  description = "AWS Region"
  default     = "eu-west-2"
}

### VPC, AZ, SG
variable "vpc_id" {
  description = "The name of the VPC where you want to create the resources"
  type        = string
  default     = null
}

variable "subnets" {
  description = "A map of subnets to availability zones"
  type        = list(string)
  default     = []
}

variable "efs_security_group_rules" {
  description = "A map of security group rule definitions to add to the security group created"
  type        = map(any)
  default     = {}
}

variable "sftp_security_group_rules" {
  description = "A map of security group rule definitions to add to the security group created"
  type        = map(any)
  default     = {}
}

variable "create_efs_security_group" {
  description = "Determines whether to create security group for EFS Mount"
  type        = bool
  default     = true
}

variable "create_sftp_security_group" {
  description = "Determines whether to create security group for EFS Mount"
  type        = bool
  default     = true
}

variable "efs_security_group_name" {
  type        = string
  description = "Security Group Name"
  default     = ""
}

variable "sftp_security_group_name" {
  type        = string
  description = "Security Group Name"
  default     = ""
}

variable "security_groups" {
  type        = list(string)
  description = "A list of security group ids that should be attached to EFS Mount"
  default     = []
}


### EFS
variable "efs_name" {
  type        = string
  description = "Efs name"
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}


variable "performance_mode" {
  type        = string
  description = "Efs performance mode"
  default     = "generalPurpose"
}

variable "throughput_mode" {
  type        = string
  description = "Efs throughput mode"
  default     = "bursting"
}

### IAM
variable "create_iam_role" {
  description = "Flag to create an IAM role for SFTP users"
  type        = bool
  default     = true
}

variable "provided_iam_role_arn" {
  type        = string
  description = "The Amazon Resource Name (ARN) of an existing IAM role that should be used by AWS Backups. The ARN should have the format `arn:aws:iam::account-id:role/role-name`. If not provided, a new IAM role will be created."
  default     = ""
  validation {
    condition     = length(var.provided_iam_role_arn) == 0 || can(regex("^arn:aws:iam::[0-9]{12}:role/.*", var.provided_iam_role_arn))
    error_message = "The provided IAM role ARN is not valid. The ARN should have the format `arn:aws:iam::account-id:role/role-name`."
  }
}

### SFTP
variable "sftp_name" {
  description = "The name of the SFTP server"
  default     = ""
}

variable "identity_provider_type" {
  description = "Identity provider type of the SFTP server"
  default     = "SERVICE_MANAGED"
}

variable "endpoint_type" {
  type        = string
  description = "Endpoint type of the SFTP server"
  default     = "PUBLIC"
}

variable "sftp_domain" {
  type        = string
  description = "Domain type of the SFTP server"
  default     = "EFS"
}

variable "home_directory" {
  description = "Home directory type of the SFTP server"
  default     = ""
  type        = string
}

variable "home_directory_type" {
  description = "Home directory type of the SFTP server"
  default     = "PATH"
  type        = string
}

variable "sftp_users" {
  description = "A map of SFTP users to create"
  type = map(object({
    uid            = number
    gid            = number
    public_key     = string
    home_directory = optional(string, null)
    restricted     = optional(bool, false)
  }))
  default = {}

  validation {
    condition = alltrue([
      for _, user in var.sftp_users : user.home_directory == null || substr(user.home_directory, 0, 1) != "/"
    ])
    error_message = "The home_directory for each user must not start with '/'."
  }
}


variable "security_policy_name" {
  type        = string
  description = "Specifies the name of the security policy that is attached to the server. Possible values are TransferSecurityPolicy-2018-11, TransferSecurityPolicy-2020-06, and TransferSecurityPolicy-2023-05. Default value is: TransferSecurityPolicy-2023-05."
  default     = "TransferSecurityPolicy-2023-05"
}

variable "logging_enabled" {
  type        = bool
  description = "Enable logging for the SFTP server - the logs will be stored in CloudWatch"
  default     = false
}

variable "is_public" {
  type        = bool
  description = "Determines whether the SFTP server should be publicly accessible"
  default     = false
}

variable "eip_ids" {
  type        = list(string)
  description = "A list of Elastic IP IDs to associate with the SFTP server"
  default     = []
}

variable "sftp_security_group_ids" {
  type        = list(string)
  description = "A list of security group ids that should be attached to the SFTP server"
  default     = []
}

variable "encrypted" {
  type        = bool
  description = "Whether to enable encryption for the file system. Default is true."
  default     = true
}

variable "kms_key_id" {
  type        = string
  description = "The ARN of the AWS Key Management Service (AWS KMS) customer master key (CMK) to be used to protect the encrypted file system. This parameter is only required if you want to use a non-default CMK. If this parameter is not specified, the default CMK for Amazon EFS is used. This ID can be in one of the following formats: Key ID - A unique identifier of the key, for example 1234abcd-12ab-34cd-56ef-1234567890ab. ARN - An Amazon Resource Name (ARN) for the key, for example arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab. Key alias - A previously created display name for a key, for example alias/projectKey1. Key alias ARN - An ARN for a key alias, for example arn:aws:kms:us-east-2:444455556666:alias/projectKey1. If KmsKeyId is specified, the Encrypted flag must also be set."
  default     = null
}

variable "enable_user_access_point" {
  description = "Determines whether to create access points for each user"
  type        = bool
  default     = false
}

variable "additional_access_points" {
  description = "Configuration for additional, general-use access points"
  type = map(object({
    path        = string
    uid         = number
    gid         = number
    permissions = optional(string, "0755")
  }))
  default = {}
}