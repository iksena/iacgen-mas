provider "aws" {
  region  = "eu-west-1"
}

resource "aws_kms_key" "terraform_state" {
  description             = "CMK for the terraform-remote-state-storage-s3-kjg S3 bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "terraform-state-storage-s3" {
  bucket = "terraform-remote-state-storage-s3-kjg"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.terraform_state.arn
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform-state-storage-s3" {
  bucket = aws_s3_bucket.terraform-state-storage-s3.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Create a DynamoDB table for locking the state file
resource "aws_dynamodb_table" "dynamodb-terraform-state-lock" {
  name           = "terraform-state-lock-dynamo"
  hash_key       = "LockID"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20

  attribute {
    name = "LockID"
    type = "S"
  }
}
