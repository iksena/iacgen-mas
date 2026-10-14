resource "aws_iam_user" "this" {
  count = var.create_iam_user ? 1 : 0

  name          = local.aws_iam_username
  path          = var.path
  force_destroy = var.force_destroy
}

resource "aws_iam_access_key" "this" {
  count = var.create_iam_user ? 1 : 0

  user = aws_iam_user.this[0].name
}

resource "aws_iam_policy" "this" {
  name        = local.aws_iam_policy
  description = local.aws_iam_policy

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "${aws_s3_bucket.this.arn}/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "${aws_s3_bucket.this.arn}"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy_attachment" "this" {
  name       = local.aws_iam_username
  users      = [aws_iam_user.this[0].name]
  policy_arn = aws_iam_policy.this.arn
}

# If var.random_suffix = true, append with random string to avoid duplication
locals {
  aws_iam_username = var.random_suffix ? "${var.aws_iam_username}-${random_string.this[0].id}" : var.aws_iam_username
  aws_iam_policy   = var.random_suffix ? "${var.aws_iam_policy}-${random_string.this[0].id}" : var.aws_iam_policy
}