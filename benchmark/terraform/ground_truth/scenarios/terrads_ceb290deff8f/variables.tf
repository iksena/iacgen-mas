variable "name" {
  type        = string
  description = "(Optional) Specify the name for the backup configuration. Default: sudo-backup-<randomstring>"
  default     = "sudo-backup"
}


variable "backup_schedule" {
  type        = string
  description = "(Optional) Backup schedule in cron format. Default: cron(0 12 * * ? *)"
  default     = "cron(0 12 * * ? *)" # Take backup at UTC 12noon i.e 4am PST
}

variable "kms_key_arn" {
  type        = string
  description = "(optional) Existing KMS Key ARN. Default: \"\""
  default     = ""
}

variable "cold_storage_after" {
  type        = number
  description = "(Optional) Specifies the number of days after creation that a recovery point is moved to cold storage."
  default     = null
}

variable "delete_after" {
  type        = number
  description = "(Optional) Specifies the number of days after creation that a recovery point is deleted. Must be 90 days greater than cold_storage_after"
  default     = null
}

variable "secondary_vault_arn" {
  type        = string
  description = "(Optional) Specifies the ARN of the secondary vault for DR."
  default     = null
}

variable "secondary_vault_cold_storage_after" {
  type        = number
  description = "(Optional) Specifies the number of days after creation that a recovery point is moved to cold storage for Secondary Vault. Default uses the value from primary vault."
  default     = null
}

variable "secondary_vault_delete_after" {
  type        = number
  description = "(Optional) Specifies the number of days after creation that a recovery point is deleted for secondary Vault. Must be 90 days greater than cold_storage_after. Default uses the value from primary vault."
  default     = null
}

# # Example
#   selection_tags = [{
#     type  = "STRINGEQUALS"
#     key   = "foo"
#     value = "bar"
#   }]
variable "selection_tags" {
  type        = list(any)
  description = "(Optional) List of objects containing tag key value and type (comparison operator)."
  default = [{

  }]
}
