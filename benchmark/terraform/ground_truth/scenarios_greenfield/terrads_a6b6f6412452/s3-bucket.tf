###### Create S3 Bucket in primary region ####

resource "aws_s3_bucket" "primary" {
  provider = aws.primary_region
  bucket   = "${var.primary_bucket_name}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "primary" {
  bucket   = aws_s3_bucket.primary.id
  provider = aws.primary_region
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "primary" {
  depends_on = [aws_s3_bucket_ownership_controls.primary]
  bucket     = aws_s3_bucket.primary.id
  provider   = aws.primary_region
  acl        = "private"
}

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
  provider = aws.primary_region
}

resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  provider                = aws.primary_region
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "primary" {
  provider            = aws.primary_region
  description         = "CMK for ${var.primary_bucket_name}"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket   = aws_s3_bucket.primary.id
  provider = aws.primary_region
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.primary.arn
    }
  }
}




###### Create S3 Bucket in  secondary region ####
resource "aws_s3_bucket" "secondary" {
  provider = aws.secondary_region
  bucket   = "${var.secondary_bucket_name}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "secondary" {
  bucket   = aws_s3_bucket.secondary.id
  provider = aws.secondary_region
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "secondary" {
  depends_on = [aws_s3_bucket_ownership_controls.secondary]
  bucket     = aws_s3_bucket.secondary.id
  provider   = aws.secondary_region
  acl        = "private"
}

resource "aws_s3_bucket_versioning" "secondary" {
  bucket = aws_s3_bucket.secondary.id
  versioning_configuration {
    status = "Enabled"
  }
  provider = aws.secondary_region
}

resource "aws_s3_bucket_public_access_block" "secondary" {
  bucket                  = aws_s3_bucket.secondary.id
  provider                = aws.secondary_region
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "secondary" {
  provider            = aws.secondary_region
  description         = "CMK for ${var.secondary_bucket_name}"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secondary" {
  bucket   = aws_s3_bucket.secondary.id
  provider = aws.secondary_region
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.secondary.arn
    }
  }
}

