resource "random_integer" "random" {
  min = 1
  max = 50000
}

resource "aws_s3_bucket" "io_files_bucket" {
  bucket        = "${random_integer.random.id}${var.io_files_bucket_name}"
  force_destroy = var.force_destroy_bucket
}

resource "aws_s3_bucket_public_access_block" "io_files_bucket" {
  bucket                  = aws_s3_bucket.io_files_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "io_files_bucket" {
  description         = "CMK for the document I/O files bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "io_files_bucket" {
  bucket = aws_s3_bucket.io_files_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.io_files_bucket.arn
    }
  }
}
