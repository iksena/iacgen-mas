variable "name" {
  type        = string
  default     = null
  description = "The Name of the bucket. If omitted, Terraform will assign a random, unique name. Conflicts with `name_prefix`."

  validation {
    condition     = var.name != null ? length(var.name) <= 63 : true
    error_message = "The name must be less than or equal to 63 characters in length"
  }
}

variable "name_prefix" {
  type        = string
  default     = null
  description = "Creates a unique bucket name beginning with the specified prefix. Conflicts with `name`."

  validation {
    condition     = var.name_prefix != null ? length(var.name_prefix) <= 37 : true
    error_message = "The name prefix must be less than or equal to 37 characters in length"
  }
}

variable "acl" {
  type        = string
  default     = "private"
  description = "The canned ACL to apply, defaults to `private`."
}

variable "block_public_acls" {
  type        = bool
  default     = true
  description = "Whether Amazon S3 should block public ACLs for this bucket."
}

variable "block_public_policy" {
  type        = bool
  default     = true
  description = "Whether Amazon S3 should block public bucket policies for this bucket."
}

variable "cors_rule" {
  type = object({
    allowed_headers = list(string)
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = list(string)
    max_age_seconds = number
  })
  default     = null
  description = "The CORS rule for the S3 bucket"
}

variable "eventbridge_enabled" {
  type        = bool
  default     = false
  description = "Whether to enable Amazon EventBridge notifications."
}

variable "force_destroy" {
  type        = bool
  default     = false
  description = "A boolean that indicates all objects should be deleted when deleting the bucket."
}

variable "ignore_public_acls" {
  type        = bool
  default     = true
  description = "Whether Amazon S3 should ignore public ACLs for this bucket."
}

variable "inventory_configuration" {
  type = map(object({
    enabled                  = optional(bool, true)
    filter_prefix            = optional(string, null)
    frequency                = optional(string, "Weekly")
    included_object_versions = optional(string, "Current")
    optional_fields          = optional(list(string), null)

    destination = object({
      account_id = string
      bucket_arn = string
      format     = optional(string, "Parquet")
      prefix     = optional(string, null)

      encryption = optional(object({
        encryption_type = string
        kms_key_id      = optional(string, null)
        }), {
        encryption_type = "sse_s3"
      })
    })
  }))
  default     = {}
  description = "Bucket inventory configuration settings"
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "The KMS key ARN used for the bucket encryption."
}

variable "lifecycle_rule" {
  type        = any
  default     = []
  description = "List of maps containing lifecycle management configuration settings."
}

variable "logging" {
  type = object({
    target_bucket = string
    target_prefix = string
  })
  default     = null
  description = "Logging configuration, logging is disabled by default."
}

variable "logging_source_bucket_arns" {
  type        = list(string)
  default     = []
  description = "Configures which source buckets are allowed to log to this bucket."
}

variable "object_lock_mode" {
  type        = string
  default     = null
  description = "The default object Lock retention mode to apply to new objects."
}

variable "object_lock_years" {
  type        = number
  default     = null
  description = "The number of years that you want to specify for the default retention period."
}

variable "object_lock_days" {
  type        = number
  default     = null
  description = "The number of days that you want to specify for the default retention period."
}

variable "object_ownership_type" {
  type        = string
  default     = "BucketOwnerEnforced"
  description = "The object ownership type for the objects in S3 Bucket, defaults to BucketOwnerEnforced."
}

variable "replication_configuration" {
  type = object({
    iam_role_arn = string
    rules = map(object({
      id                  = string
      dest_bucket         = string
      dest_storage_class  = optional(string, null)
      replica_kms_key_arn = optional(string, null)

      source_selection_criteria = optional(object({
        replica_modifications     = optional(bool, false)
        sse_kms_encrypted_objects = optional(bool, false)
      }))
    }))
  })
  default     = null
  description = "Bucket replication configuration settings, specify the rules map keys as integers as these are used to determine the priority of the rules in case of conflict."
}

variable "restrict_public_buckets" {
  type        = bool
  default     = true
  description = "Whether Amazon S3 should restrict public bucket policies for this bucket."
}

variable "policy" {
  type        = string
  default     = null
  description = "A valid bucket policy JSON document."
}

variable "versioning" {
  type        = bool
  default     = false
  description = "Versioning is a means of keeping multiple variants of an object in the same bucket."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "A mapping of tags to assign to the bucket."
}
