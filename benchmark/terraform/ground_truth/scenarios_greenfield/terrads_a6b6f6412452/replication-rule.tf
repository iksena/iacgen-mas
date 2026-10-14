resource "aws_iam_role" "replication" {
  provider           = aws.primary_region
  name               = "devopscaptain-tf-iam-role-replication"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "replication" {
  provider = aws.primary_region
  statement {
    effect = "Allow"

    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]

    resources = [aws_s3_bucket.primary.arn]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]

    resources = ["${aws_s3_bucket.primary.arn}/*"]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]

    resources = ["${aws_s3_bucket.secondary.arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.primary.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:Encrypt"]
    resources = [aws_kms_key.secondary.arn]
  }
}

resource "aws_iam_policy" "replication" {
  provider = aws.primary_region
  name     = "devopscaptain-iam-role-policy-replication"
  policy   = data.aws_iam_policy_document.replication.json
}

resource "aws_iam_role_policy_attachment" "replication" {
  provider   = aws.primary_region
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

resource "aws_s3_bucket_replication_configuration" "replication" {
  provider   = aws.primary_region
  depends_on = [aws_s3_bucket_versioning.primary]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.primary.id

  rule {
    id     = "rule-1"
    status = "Enabled"

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.secondary.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.secondary.arn
      }
    }
  }
}