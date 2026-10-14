variable "bucket_name" {
  description = "The name of the S3 bucket for CloudTrail logs. If empty, a name will be generated."
  type        = string
  default     = ""
}

variable "is_organization_trail" {
  description = "Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account."
  type        = bool
  default     = false
}

variable "bucket_force_destroy" {
  description = "A boolean that indicates all objects should be deleted from the bucket so that the bucket can be destroyed without error"
  type        = bool
  default     = true
}

variable "cloudtrail_name" {
  description = "The name of the CloudTrail. If empty, a name will be generated."
  type        = string
  default     = ""
}

variable "include_global_service_events" {
  description = "Specifies whether the trail is publishing events from global services such as IAM to the log files"
  type        = bool
  default     = true
}

variable "is_multi_region_trail" {
  description = "Specifies whether the trail is created in the current region or in all regions"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enables logging for the trail"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Specifies the number of days you want to retain log events in the CloudWatch log group"
  type        = number
  default     = 90
}

variable "create_sns_topic" {
  description = "Specifies whether to create an SNS topic for CloudTrail notifications"
  type        = bool
  default     = false
}

variable "sns_topic_name" {
  description = "The name of the SNS topic to create for CloudTrail notifications. If empty, a name will be generated."
  type        = string
  default     = ""
}

variable "existing_sns_topic_arn" {
  description = "The ARN of an existing SNS topic to use for CloudTrail notifications. Only used if create_sns_topic is false."
  type        = string
  default     = ""
}

variable "enable_s3_bucket_versioning" {
  description = "Enable versioning on the S3 bucket"
  type        = bool
  default     = false
}

variable "decrypt_role_arn" {
  description = "ARN of the IAM role allowed to decrypt CloudTrail log files. If provided, a policy statement will be added to the KMS key to allow decryption."
  type        = string
  default     = ""
}

variable "include_management_events" {
  type    = bool
  default = true
}

variable "data_resource_type" {
  type    = string
  default = "AWS::S3::Object"
}

variable "data_resources" {
  type = list(object({
    type   = string
    values = list(string)
  }))
  default     = []
  description = "List of data resources to log events for. Each object should contain 'type' and 'values' keys."
}

variable "rw_type" {
  description = "Specifies whether to log read-only events, write-only events, or all events for data resources."
  type        = string
  default     = "All"
  validation {
    condition     = contains(["ReadOnly", "WriteOnly", "All"], var.rw_type)
    error_message = "rw_type must be one of ReadOnly, WriteOnly, or All."
  }
}

variable "insight_selector" {
  description = "List of insight types to enable for the trail. Valid values are ApiCallRateInsight and ApiErrorRateInsight."
  type = list(object({
    insight_type = string
  }))
  default = []
  validation {
    condition     = alltrue([for insight in var.insight_selector : contains(["ApiCallRateInsight", "ApiErrorRateInsight"], insight.insight_type)])
    error_message = "Invalid insight type. Allowed values are ApiCallRateInsight and ApiErrorRateInsight."
  }
}