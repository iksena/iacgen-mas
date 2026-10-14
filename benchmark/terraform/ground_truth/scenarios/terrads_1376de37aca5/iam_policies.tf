data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "role-trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "manage-self" {
  statement {
    sid = "AllowUsersToManageTheirUser"

    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
      "iam:CreateAccessKey",
      "iam:ChangePassword",
      "iam:DeleteLoginProfile",
      "iam:List*",
      "iam:Get*",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/&{aws:username}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/&{aws:username}",
    ]
  }

  statement {
    sid = "AllowUsersToDeactivateTheirOwnVirtualMFADevice"

    actions = [
      "iam:DeactivateMFADevice",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/&{aws:username}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/&{aws:username}",
    ]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }

  statement {
    sid = "AllowUsersToListMFADevicesandUsersForConsole"

    actions = [
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ListUsers",
    ]

    resources = ["*"]
  }

  statement {
    actions   = ["iam:GetAccountPasswordPolicy"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "assume-role-admin" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.admin.arn]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}
