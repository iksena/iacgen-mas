resource "aws_iam_policy" "suport" {
  name = "SuportPolicy"
  description = "Policy destinated to suport team"
  policy = data.aws_iam_policy_document.suport.json
}
resource "aws_iam_policy" "billing" {
  name = "BillingPolicy"
  description = "Policy destinated to billing team"
  policy = data.aws_iam_policy_document.billing.json
}
data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}

resource "aws_iam_group" "billing" {
  name = "BillingGroup"
  path = "/"
}
resource "aws_iam_group" "admin" {
  name = "AdminGroup"
  path = "/"
}
resource "aws_iam_group" "suport" {
  name = "SuportGroup"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "billing" {
  group = aws_iam_group.billing.name
  policy_arn = aws_iam_policy.billing.arn
}
resource "aws_iam_group_policy_attachment" "admin" {
  group = aws_iam_group.admin.name
  policy_arn = data.aws_iam_policy.admin.arn
}
resource "aws_iam_group_policy_attachment" "suport" {
  group = aws_iam_group.suport.name
  policy_arn = aws_iam_policy.suport.arn
}

resource "aws_iam_user" "billing" {
  name = "Billing"
  path = "/"
}
resource "aws_iam_user" "admin" {
  name = "Admin"
  path = "/"
}
resource "aws_iam_user" "suport" {
  name = "Suport"
  path = "/"
}

resource "aws_iam_user_group_membership" "billing" {
  user = aws_iam_user.billing.name
  groups = [aws_iam_group.billing.name]
}
resource "aws_iam_user_group_membership" "admin" {
  user = aws_iam_user.admin.name
  groups = [aws_iam_group.admin.name]
}
resource "aws_iam_user_group_membership" "suport" {
  user = aws_iam_user.suport.name
  groups = [aws_iam_group.suport.name]
}

resource "aws_iam_user_login_profile" "billing" {
  user = aws_iam_user.billing.name
  password_length = var.minimum_password_length
}
resource "aws_iam_user_login_profile" "admin" {
  user = aws_iam_user.admin.name
  password_length = var.minimum_password_length
}
resource "aws_iam_user_login_profile" "suport" {
  user = aws_iam_user.suport.name
  password_length = var.minimum_password_length
}
