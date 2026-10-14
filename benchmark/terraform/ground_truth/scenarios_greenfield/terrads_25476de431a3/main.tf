data "aws_region" "current" {}

resource "random_string" "this" {
  count = var.random_suffix ? 1 : 0

  length  = var.random_string_length
  numeric = true
  special = false
  upper   = false
}

resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name
  force_destroy = true

  tags = {
    Name = local.bucket_name
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "this" {
  description         = "CMK for ${local.bucket_name} S3 bucket"
  enable_key_rotation = true
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

resource "aws_s3_object" "this" {
  count = var.upload_image ? 1 : 0

  bucket = aws_s3_bucket.this.id
  key    = local.s3_key
  source = "${path.cwd}/${var.image_filename}"
}

# If var.random_suffix = true, append with random string to avoid duplication
locals {
  bucket_name         = var.random_suffix ? "${var.bucket_name}-${random_string.this[0].id}" : var.bucket_name
  s3_key              = var.create_folder ? "${var.s3_folder}/${var.image_filename}" : var.image_filename
  s3_dpath            = var.create_folder ? "${aws_s3_bucket.this.bucket}/${var.s3_folder}" : aws_s3_bucket.this.bucket
  s3_fqdn_path_url    = "https://s3.${data.aws_region.current.name}.amazonaws.com"
  s3_fqdn_virtual_url = "https://${aws_s3_bucket.this.bucket}.s3.${data.aws_region.current.name}.amazonaws.com"
}