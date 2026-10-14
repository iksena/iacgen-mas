resource "aws_s3_bucket" "results" {
    bucket = "${var.result_bucket}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_kms_key" "results_bucket" {
  description         = "CMK for the Batch results S3 bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.results_bucket.arn
    }
  }
}