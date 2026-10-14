### event bridge
variable "bus" {
  description = "Event bus configuration"
  default     = {}
  validation {
    condition     = var.bus != null
    error_message = "Configuration for custom eventbridge bus must not be null."
  }
}

variable "rules" {
  description = "A configuration list of event rules"
  default     = []
  validation {
    condition     = var.rules != null
    error_message = "List of eventbridge rules is not valid."
  }
}

variable "targets" {
  description = "A configuration list of event route target definitions"
  type        = any
  default     = []
  validation {
    condition     = var.targets != null
    error_message = "List of eventbridge rule targets is not valid."
  }
}

### description
variable "name" {
  description = "Event bus name"
  type        = string
  default     = null
}

### tags
variable "tags" {
  description = "The key-value maps for tagging"
  type        = map(string)
  default     = {}
}
