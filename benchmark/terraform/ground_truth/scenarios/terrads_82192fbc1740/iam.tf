resource "aws_iam_role" "sftp_user_role" {
  count = var.create_iam_role ? 1 : 0

  name = "${var.sftp_name}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "transfer.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "sftp_user_policy" {
  count = var.create_iam_role ? 1 : 0

  name   = "${var.sftp_name}-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.sftp_user_policy[count.index].json
}

resource "aws_iam_role_policy_attachment" "sftp_user_policy_attachment" {
  count      = var.create_iam_role ? 1 : 0
  policy_arn = aws_iam_policy.sftp_user_policy[count.index].arn
  role       = aws_iam_role.sftp_user_role[count.index].name
}

resource "aws_iam_policy" "logging" {
  count = var.logging_enabled ? 1 : 0

  name_prefix = "${var.sftp_name}-logging-"
  policy      = join("", data.aws_iam_policy_document.logging[*].json)

  tags = var.tags
}

resource "aws_iam_role" "logging" {
  count = var.logging_enabled ? 1 : 0

  name_prefix         = "${var.sftp_name}-logging-"
  assume_role_policy  = join("", data.aws_iam_policy_document.assume_role_policy[*].json)
  managed_policy_arns = [join("", aws_iam_policy.logging[*].arn)]

  tags = var.tags
}