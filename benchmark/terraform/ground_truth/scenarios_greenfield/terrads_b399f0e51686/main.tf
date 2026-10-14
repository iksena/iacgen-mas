data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Add this to the top of main.tf
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = var.bucket_name != "" ? var.bucket_name : "cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}-${random_string.suffix.result}"
  force_destroy = var.bucket_force_destroy
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_bucket_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = var.enable_s3_bucket_versioning ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck20150319"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name != "" ? var.cloudtrail_name : "main-trail-${data.aws_region.current.name}-${random_string.suffix.result}"}"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite20150319"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name != "" ? var.cloudtrail_name : "main-trail-${data.aws_region.current.name}-${random_string.suffix.result}"}"
          }
        }
      } 
    ]
  })
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/cloudtrail-${data.aws_region.current.name}-${random_string.suffix.result}"
  target_key_id = aws_kms_key.cloudtrail.key_id
}


resource "aws_kms_key_policy" "cloudtrail" {
  key_id = aws_kms_key.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "Key policy for CloudTrail"
    Statement = concat([
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:${data.aws_partition.current.partition}:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "Allow CloudWatch Log Group Encrypt"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:${data.aws_partition.current.partition}:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      },
      {
        Sid    = "AllowS3ToUseTheKeyForBucketEncryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ],
    var.decrypt_role_arn != "" ? [
      {
        Sid    = "AllowRoleToDecryptCloudTrailFiles"
        Effect = "Allow"
        Principal = {
          AWS = var.decrypt_role_arn
        }
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.cloudtrail.arn
        Condition = {
          Null = {
            "kms:EncryptionContext:${data.aws_partition.current.partition}:cloudtrail:arn" = "false"
          }
        }
      }
    ] : [])
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.cloudtrail_name != "" ? var.cloudtrail_name : "main-trail-${data.aws_region.current.name}-${random_string.suffix.result}"}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "cloudwatch_logs_role" {
  name = "cloudwatch-logs-role-${data.aws_region.current.name}-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs_policy" {
  name = "cloudwatch-logs-policy-${data.aws_region.current.name}"
  role = aws_iam_role.cloudwatch_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

resource "aws_sns_topic" "cloudtrail_alerts" {
  count = var.create_sns_topic ? 1 : 0
  name  = var.sns_topic_name != "" ? var.sns_topic_name : "cloudtrail-alerts-${data.aws_region.current.name}"
}

resource "aws_sns_topic_policy" "cloudtrail_alerts" {
  count  = var.create_sns_topic ? 1 : 0
  arn    = aws_sns_topic.cloudtrail_alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.cloudtrail_alerts[0].arn
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = var.cloudtrail_name != "" ? var.cloudtrail_name : "main-trail-${data.aws_region.current.name}-${random_string.suffix.result}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
  enable_logging                = var.enable_logging
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudwatch_logs_role.arn
  is_organization_trail         = var.is_organization_trail
  sns_topic_name                = var.create_sns_topic ? aws_sns_topic.cloudtrail_alerts[0].arn : var.existing_sns_topic_arn

  # Always include management events
  event_selector {
    read_write_type           = var.rw_type
    include_management_events = var.include_management_events

    dynamic "data_resource" {
      for_each = var.data_resources
      content {
        type   = data_resource.value.type
        values = data_resource.value.values
        }
      }
    }

    dynamic "insight_selector" {
      for_each = var.insight_selector
      content {
        insight_type = insight_selector.value.insight_type
      }
  }
}