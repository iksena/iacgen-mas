#-------------------------------------------------------------------------------------
# Shared CMK for S3/Athena encryption at rest
#-------------------------------------------------------------------------------------
resource "aws_kms_key" "data_lake" {
  description         = "CMK for data-lake S3 buckets and Athena database encryption"
  enable_key_rotation = true
}

resource "aws_kms_alias" "data_lake" {
  name          = "alias/${var.bucket_artefact_glue}-data-lake"
  target_key_id = aws_kms_key.data_lake.key_id
}

#-------------------------------------------------------------------------------------
# Public access block (AWS-0086/0087/0091/0093) for every bucket
#-------------------------------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "artefact_glue" {
  bucket                  = aws_s3_bucket.artefact_glue.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "lake_staging" {
  bucket                  = aws_s3_bucket.lake_staging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "lake_bronze" {
  bucket                  = aws_s3_bucket.lake_bronze.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "lake_silver" {
  bucket                  = aws_s3_bucket.lake_silver.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "lake_gold" {
  bucket                  = aws_s3_bucket.lake_gold.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "logdir" {
  bucket                  = aws_s3_bucket.logdir.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#-------------------------------------------------------------------------------------
# Server-side encryption with the CMK above (AWS-0132) for every bucket
#-------------------------------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "artefact_glue" {
  bucket = aws_s3_bucket.artefact_glue.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake_staging" {
  bucket = aws_s3_bucket.lake_staging.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake_bronze" {
  bucket = aws_s3_bucket.lake_bronze.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake_silver" {
  bucket = aws_s3_bucket.lake_silver.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake_gold" {
  bucket = aws_s3_bucket.lake_gold.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logdir" {
  bucket = aws_s3_bucket.logdir.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_lake.arn
    }
  }
}
