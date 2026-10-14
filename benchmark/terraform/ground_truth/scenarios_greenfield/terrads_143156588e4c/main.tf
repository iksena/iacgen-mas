#--------------------------------------------------------------
# This module creates the S3 resource for Cloud trail
#--------------------------------------------------------------
variable "name" { default = "benchmark" }
variable "aws_region" { default = "us-east-1" }

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.name}-cloudtrail-${var.aws_region}"
  force_destroy = true
  policy        = data.aws_iam_policy_document.cloudtrail.json
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "cloudtrail" {
  description         = "CMK for the CloudTrail log bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
  }
}

data "aws_iam_policy_document" "cloudtrail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${var.name}-cloudtrail-${var.aws_region}"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.name}-cloudtrail-${var.aws_region}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
