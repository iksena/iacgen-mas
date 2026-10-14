# DEPRECATION WARNING: This code has been deprecated
# The maintained & current code can be found at src/mlstacks/terraform/
# under the same relative location.

# creste s3 bucket for storing artifacts
resource "aws_s3_bucket" "zenml-artifact-store" {
  bucket        = "${local.prefix}-${local.s3.name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(
    local.tags,
    {
      name = "zenml-artifact-store"
    }
  )
}

resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = aws_s3_bucket.zenml-artifact-store.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "example" {
  depends_on = [aws_s3_bucket_ownership_controls.example]
  bucket     = aws_s3_bucket.zenml-artifact-store.id
  acl        = "private"
}

# block public access to the bucket
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.zenml-artifact-store.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "zenml_artifact_store" {
  description             = "CMK for the zenml-artifact-store S3 bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "zenml_artifact_store" {
  bucket = aws_s3_bucket.zenml-artifact-store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.zenml_artifact_store.arn
    }
  }
}
