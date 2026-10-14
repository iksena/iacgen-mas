locals {
  create_s3_bucket_policy = length(var.bucket_policies) > 0
}


resource "aws_s3_bucket" "this" {
  bucket              = var.bucket
  force_destroy       = var.bucket_force_destroy
  object_lock_enabled = var.bucket_object_lock_enabled

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "this" {
  description             = "CMK for the ${coalesce(var.bucket, "auto-generated")} S3 bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
  }
}


data "aws_iam_policy_document" "this" {
  for_each = local.create_s3_bucket_policy ? var.bucket_policies : {}

  policy_id = each.value.id
  version   = each.value.version

  dynamic "statement" {
    for_each = each.value.statements

    content {
      sid       = statement.value.sid
      actions   = statement.value.actions
      effect    = statement.value.effect
      resources = statement.value.resources

      dynamic "principals" {
        for_each = statement.value.principals
        iterator = principal

        content {
          identifiers = principal.value.identifiers
          type        = principal.value.type
        }
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each = local.create_s3_bucket_policy ? data.aws_iam_policy_document.this : {}

  bucket = aws_s3_bucket.this.id
  policy = each.value.json
}
