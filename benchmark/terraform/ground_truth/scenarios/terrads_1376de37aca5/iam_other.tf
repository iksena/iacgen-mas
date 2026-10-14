resource "aws_iam_policy" "manage-self-other" {
  name        = "${module.other-label.id}-permit-manage-self"
  description = "Allow other users to manage their own User"
  policy      = data.aws_iam_policy_document.manage-self.json
}

resource "aws_iam_group" "other" {
  name = module.other-label.id
}

resource "aws_iam_group_policy_attachment" "manage-self-other" {
  group      = aws_iam_group.other.name
  policy_arn = aws_iam_policy.manage-self-other.arn
}

resource "aws_iam_group_membership" "other" {
  count = length(var.other_user_names) > 0 ? 1 : 0
  name  = module.other-label.id
  group = aws_iam_group.other.id
  users = var.other_user_names
}
