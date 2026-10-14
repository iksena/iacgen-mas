variable "visibility_timeout_seconds" {
  type        = number
  default     = 30
  description = "The visibility timeout for the queue. An integer from 0 to 43200 (12 hours)."
}

variable "message_retention_seconds" {
  type        = number
  default     = 345600
  description = "The number of seconds Amazon SQS retains a message. Integer representing seconds, from 60 (1 minute) to 1209600 (14 days)."
}

variable "max_message_size" {
  type        = number
  default     = 262144
  description = "The limit of how many bytes a message can contain before Amazon SQS rejects it. An integer from 1024 bytes (1 KiB) up to 262144 bytes (256 KiB)."
}

variable "delay_seconds" {
  type        = number
  default     = 0
  description = "The time in seconds that the delivery of all messages in the queue will be delayed. An integer from 0 to 900 (15 minutes)."
}

variable "receive_wait_time_seconds" {
  type        = number
  default     = 0
  description = "The time for which a ReceiveMessage call will wait for a message to arrive (long polling) before returning. An integer from 0 to 20 (seconds)."
}

variable "policy" {
  type        = string
  default     = null
  description = "The JSON policy for the SQS queue."
}

variable "redrive_policy" {
  type        = string
  default     = null
  description = "The JSON policy to set up the Dead Letter Queue."
}

variable "fifo_queue_enabled" {
  type        = bool
  default     = false
  description = "Boolean designating a FIFO queue."
}

variable "content_based_deduplication_enabled" {
  type        = bool
  default     = false
  description = "Enables content-based deduplication for FIFO queues."
}

variable "kms_master_key_id" {
  type        = string
  default     = null
  description = "The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK."
}

variable "kms_data_key_reuse_period_seconds" {
  type        = number
  default     = 300
  description = "The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again. An integer representing seconds, between 60 seconds (1 minute) and 86,400 seconds (24 hours)."
}

variable "deduplication_scope" {
  type        = string
  default     = null
  description = "Specifies whether message deduplication occurs at the message group or queue level. Valid values are `messageGroup` and `queue`."

  validation {
    condition     = var.deduplication_scope == null ? true : contains(["messageGroup", "queue"], var.deduplication_scope)
    error_message = "Allowed values: `messageGroup`, `queue`."
  }
}

variable "fifo_throughput_limit" {
  type        = string
  default     = null
  description = "Specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. Valid values are `perQueue` and `perMessageGroupId`."

  validation {
    condition     = var.fifo_throughput_limit == null ? true : contains(["perQueue", "perMessageGroupId"], var.fifo_throughput_limit)
    error_message = "Allowed values: `perQueue`, `perMessageGroupId`."
  }
}

variable "prebuilt_policy" {
  type = object(
    {
      enabled = optional(bool, false)
      sid     = optional(string, "AllowSendMessage")
      actions = optional(list(string), ["sqs:SendMessage"])
      principals = optional(object(
        {
          type        = optional(string, "Service")
          identifiers = optional(list(string), ["events.amazonaws.com"])
        }
      ), {})
    }
  )
  default     = {}
  description = "A prebuilt AWS policy which will be assigned to SQS queue."
}
