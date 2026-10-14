resource "aws_iam_group" "ersia_devel_group" {
    name = "Ersia_Devel_Group"
    path = "/"
}

resource "aws_iam_group" "ersia_guest_group" {
    name = "Ersia_Guest_Group"
    path = "/"
}

data "aws_iam_policy" "ersia_devel_access" {
    name = "ReadOnlyAccess"
}

data "aws_iam_policy" "ersia_guest_access" {
    name = "IAMReadOnlyAccess"
}

resource "aws_iam_group_policy_attachment" "ersia_devel_group_policy_attach" {
    group      = aws_iam_group.ersia_devel_group.name
    policy_arn = data.aws_iam_policy.ersia_devel_access.arn
}

resource "aws_iam_group_policy_attachment" "ersia_guest_group_policy_attach" {
    group      = aws_iam_group.ersia_guest_group.name
    policy_arn = data.aws_iam_policy.ersia_guest_access.arn
}