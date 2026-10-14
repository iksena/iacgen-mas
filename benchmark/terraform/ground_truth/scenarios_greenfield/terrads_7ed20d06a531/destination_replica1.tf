data "aws_caller_identity" "replica1_bucket_owner" {
    provider = aws.replica1
}

resource "aws_kms_key" "replicakey1" {
    provider                = aws.replica1
    description             = "This key is used to encrypt dest bucket objects"
    deletion_window_in_days = 10
}

resource "aws_kms_alias" "replicakey1"  {
    provider      = aws.replica1
    name          = "alias/replicakey1"
    target_key_id = aws_kms_key.replicakey1.key_id
}

resource "aws_s3_bucket" "replica1" {
    provider         = aws.replica1
    count            = sum([for _, names in var.s3_bucket_names : length(names)])
    acl              = "private"
    bucket           = "${flatten([for _, names in var.s3_bucket_names : names ])[count.index]}-replica1-${data.aws_caller_identity.replica1_bucket_owner.account_id}"

    versioning {
        enabled = true
    }

    server_side_encryption_configuration {
        rule {
            apply_server_side_encryption_by_default {
                kms_master_key_id = aws_kms_key.replicakey1.arn
                sse_algorithm     = "aws:kms"
            }
        }
    }

    tags = {
        Env = var.env
    }
}
resource "aws_s3_bucket_public_access_block" "replica1" {
    provider = aws.replica1
    count    = sum([for _, names in var.s3_bucket_names : length(names)])
    bucket   = aws_s3_bucket.replica1[count.index].id

    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
}
