# Boolean to determine if name will be appended with random string
variable "random_suffix" {
  description = "Set to true to append random suffix."
  type        = bool
  default     = true
}

# Length of random string to be appended to the name
variable "random_string_length" {
  description = "Random string length."
  type        = number
  default     = 4
}

variable "create_iam_user" {
  description = "Set to true to create a new the IAM user."
  type        = bool
  default     = true
}

variable "create_folder" {
  description = "Set to true create a folder."
  type        = bool
  default     = true
}

variable "upload_image" {
  description = "Set to true to upload image."
  type        = bool
  default     = false
}

variable "aws_iam_username" {
  description = "IAM user name"
  type        = string
  default     = "zedcloud-s3-user"
}

variable "aws_iam_policy" {
  description = "S3 read-only IAM policy name"
  type        = string
  default     = "zedcloud-s3-policy"
}

variable "path" {
  description = "Desired path for the IAM user."
  type        = string
  default     = "/"
}

variable "force_destroy" {
  description = "When destroying IAM user, destroy even if it has non-Terraform-managed IAM access keys, login profile or MFA devices. Without force_destroy a user with non-Terraform-managed access keys and login profile will fail to be destroyed."
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "S3 bucket name."
  type        = string
  default     = "zedcloud"
}

variable "s3_folder" {
  description = "S3 bucket folder."
  type        = string
  default     = "my-folder"
}

variable "zedcloud_datastore_name" {
  description = "Zedcloud Data Store name."
  type        = string
  default     = "my-s3-data-store"
}

variable "zedcloud_image_name" {
  description = "Zededa App Image name."
  type        = string
  default     = "my-image"
}

variable "image_filename" {
  description = "Image filename."
  type        = string
  default     = "my-file.qcow2"
}

variable "image_format" {
  description = "Image format."
  type        = string
  default     = "qcow2"
}