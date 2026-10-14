variable s3bucket_arns {
  type        = list(string)
  default     = []
  description = "The bucket ARNs that the user will be able to upload to"
}

variable s3_paths {
  type        = map
  default     = {}
  description = "The path within the buckets that the user may upload to. Map of bucket name => path"
}

variable lambda_arns {
  type        = list(string)
  default     = []
  description = "Lambda function ARNs that the user may update the source code for"
}

variable username {
  type    = string
  default = "DeploymentUser"
}

variable tags {
  type    = map
  default = {}
}
