variable "ami_id" {
  description = "The AMI ID to use in the AWS Batch compute environment. Should be compatible with ECS. (Unused now that ec2_configuration relies on AWS's own default ECS_AL2 AMI instead of an override; kept declared since Terraform still requires a value for every declared root variable.)"
  type        = string
  default     = "unused"
}

variable "result_bucket" {
  description = "A bucket into which we place results from pipeline tasks."
  type        = string
  default     = "benchmark-batch-results"
}

variable "max_cpu" {
  description = "The maximum number of vCPUs in the Batch environment"
  type        = number
  default     = 4
}

variable "instance_types" {
  description = "The types of instances that are available in the environment. Specific machines can be used to force parallelization in desired ways."
  type        = list(any)
  default     = ["optimal"]
}
