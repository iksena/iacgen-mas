data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

data "aws_iam_policy_document" "logging" {
  count = var.logging_enabled ? 1 : 0

  statement {
    sid    = "AWSTransferLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:CreateLogGroup",
      "logs:PutLogEvents"
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "sftp_user_policy" {
  count = var.create_iam_role ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientRootAccess",
      "elasticfilesystem:ClientRead",
      "elasticfilesystem:ClientExecute",
      "elasticfilesystem:DescribeMountTargets",
      "elasticfilesystem:ClientWrite"
    ]

    resources = [
      aws_efs_file_system.efs.arn
    ]
  }
}

data "aws_iam_policy_document" "assume_role_policy" {
  count = var.logging_enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }
  }
}