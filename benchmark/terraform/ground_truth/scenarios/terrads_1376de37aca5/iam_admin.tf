resource "aws_iam_policy" "manage-self-admin" {
  name        = "${module.admin-label.id}-permit-manage-self"
  description = "Allow admin users to manage their own User"
  policy      = data.aws_iam_policy_document.manage-self.json
}

resource "aws_iam_policy" "assume-role-admin" {
  name        = "${module.admin-label.id}-permit-assume-role"
  description = "Allow assuming admin role"
  policy      = data.aws_iam_policy_document.assume-role-admin.json
}

resource "aws_iam_group" "admin" {
  name = module.admin-label.id
}

resource "aws_iam_role" "admin" {
  name               = module.admin-label.id
  assume_role_policy = data.aws_iam_policy_document.role-trust.json
}

resource "aws_iam_group_policy_attachment" "assume-role-admin" {
  group      = aws_iam_group.admin.name
  policy_arn = aws_iam_policy.assume-role-admin.arn
}

resource "aws_iam_group_policy_attachment" "manage-self-admin" {
  group      = aws_iam_group.admin.name
  policy_arn = aws_iam_policy.manage-self-admin.arn
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group_membership" "admin" {
  count = length(var.admin_user_names) > 0 ? 1 : 0
  name  = module.admin-label.id
  group = aws_iam_group.admin.id
  users = var.admin_user_names
}
