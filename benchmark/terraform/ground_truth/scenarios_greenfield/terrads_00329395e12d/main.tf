terraform {
  required_version = ">= 1.1.0"
}

provider "aws" {
  region = "eu-north-1"
}

data "aws_caller_identity" "current" {}

locals {
  aws_account = data.aws_caller_identity.current.account_id
}

resource "aws_kms_key" "buckets" {
  description             = "Shared CMK for this scenario's S3 buckets"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "bucket2" {
  bucket = "${data.aws_caller_identity.current.account_id}-bucket2"
}

resource "aws_s3_bucket_public_access_block" "bucket2" {
  bucket = aws_s3_bucket.bucket2.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket2" {
  bucket = aws_s3_bucket.bucket2.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.buckets.arn
    }
  }
}

output "bucket2" {
  value = aws_s3_bucket.bucket2.bucket
}

resource "aws_s3_bucket" "bucketX" {
  count  = 2
  bucket = "${data.aws_caller_identity.current.account_id}-bucket${count.index + 3}"
}

resource "aws_s3_bucket_public_access_block" "bucketX" {
  count  = 2
  bucket = aws_s3_bucket.bucketX[count.index].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucketX" {
  count  = 2
  bucket = aws_s3_bucket.bucketX[count.index].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.buckets.arn
    }
  }
}

output "bucketX" {
  value = ["${aws_s3_bucket.bucketX.*.bucket}"]
}

locals {
  buckets = {
    bucket101 = "bucket101"
    bucket102 = "bucket102"
  }
}

resource "aws_s3_bucket" "bucketE" {
  for_each = local.buckets
  bucket   = "${local.aws_account}-${each.value}"
}

resource "aws_s3_bucket_public_access_block" "bucketE" {
  for_each = local.buckets
  bucket   = aws_s3_bucket.bucketE[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucketE" {
  for_each = local.buckets
  bucket   = aws_s3_bucket.bucketE[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.buckets.arn
    }
  }
}

output "bucketE" {
    value = toset([
        for bucketE in aws_s3_bucket.bucketE : bucketE.bucket
    ])
}

locals {
  bucketlist = [
      "bucket103",
      "bucket104"
  ]
}

resource "aws_s3_bucket" "bucketL" {
  for_each = toset(local.bucketlist)
  bucket = "${local.aws_account}-${each.key}"
}

resource "aws_s3_bucket_public_access_block" "bucketL" {
  for_each = toset(local.bucketlist)
  bucket   = aws_s3_bucket.bucketL[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucketL" {
  for_each = toset(local.bucketlist)
  bucket   = aws_s3_bucket.bucketL[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.buckets.arn
    }
  }
}

output "bucketL" {
    value = toset([
        for bucketL in aws_s3_bucket.bucketL : bucketL.bucket
    ])
}
