variable "default_sender_id_string" {
  type    = string
  default = null
}

variable "default_sms_type" {
  type    = string
  default = "Transactional"
  validation {
    condition     = contains(["Promotional", "Transactional"], var.default_sms_type)
    error_message = "Invalid SMS type"
  }
}

variable "delivery_status_success_sampling_rate" {
  type    = number
  default = 0
}

variable "iam_role_arn_delivery_status" {
  type    = string
  default = null
}

variable "monthly_spend_limit" {
  type    = number
  default = null
}

variable "usage_report_s3_bucket" {
  type    = string
  default = null
}
