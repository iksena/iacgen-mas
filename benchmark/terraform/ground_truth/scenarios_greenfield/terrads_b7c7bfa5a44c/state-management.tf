######## Terraform State managemnet s3 bucket
resource "aws_s3_bucket" "terraform_state_bucket" {
    bucket = "near-frontend-${lower(var.AWS_ENVIRONMENT_NAME)}-terraform-state-${data.aws_caller_identity.current.account_id}"

    tags = {
        Name = "S3 Remote Terraform State Store"
        Environment = var.AWS_ENVIRONMENT_NAME
    }
}

resource "aws_s3_bucket_ownership_controls" "terraform_state_bucket" {
  bucket = aws_s3_bucket.terraform_state_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "terraform_state_bucket_securing" {
  depends_on = [aws_s3_bucket_ownership_controls.terraform_state_bucket]
  bucket     = aws_s3_bucket.terraform_state_bucket.id
  acl        = "private"
}

resource "aws_s3_bucket_public_access_block" "terraform_state_bucket" {
  bucket                  = aws_s3_bucket.terraform_state_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "terraform_state_bucket_versioning" {
  bucket = aws_s3_bucket.terraform_state_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "terraform_state_bucket_kms_key" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_bucket_encryption" {
  bucket = aws_s3_bucket.terraform_state_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_state_bucket_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

######## Terraform State managemnet dynmodb
resource "aws_dynamodb_table" "terraform-lock" {
    name           = "near-frontend-terraform-state"
    read_capacity  = 5
    write_capacity = 5
    hash_key       = "LockID"
    attribute {
        name = "LockID"
        type = "S"
    }
    tags = {
        "Name" = "DynamoDB Terraform State Lock Table"
        Environment = var.AWS_ENVIRONMENT_NAME
    }
}
