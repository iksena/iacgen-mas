# Only CloudFront can read from this bucket, otherwise it's private
data "aws_iam_policy_document" "cfweb" {
  statement {
    sid       = "AllowCloudFrontServicePrincipal"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.website.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.web.arn]
    }

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket" "website" {
  bucket = local.s3_bucket_name == "" ? local.s3_fallback_name : local.s3_bucket_name
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_public_access_block" "website" {
  bucket                  = aws_s3_bucket.website.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "website" {
  description         = "CMK for the website bucket"
  enable_key_rotation = true
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAdmin", Effect = "Allow", Action = "kms:*", Resource = "*", Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" } },
    { Sid = "AllowCloudFrontDecrypt", Effect = "Allow", Action = "kms:Decrypt", Resource = "*", Principal = { Service = "cloudfront.amazonaws.com" },
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.web.arn } } }
  ] })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = aws_s3_bucket.website.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.website.arn
    }
  }
}

resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id
  policy = data.aws_iam_policy_document.cfweb.json
}

resource "aws_s3_bucket_versioning" "website" {
  count  = var.s3_bucket_versioning == true ? 1 : 0
  bucket = aws_s3_bucket.website.id
  versioning_configuration {
    status = "Enabled"
  }
}
