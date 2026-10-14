resource "aws_iam_user" "test" {
  name = "TestUser-rwwise.dev"
  path = "/system/"

  tags = local.tags
}

resource "aws_iam_access_key" "test" {
  user = aws_iam_user.test.name
}

data "aws_iam_policy_document" "test" {
  statement {
    effect = "Allow"
    actions = ["codebuild:BatchGet*",
      "codebuild:GetResourcePolicy",
      "codebuild:List*",
      "codebuild:DescribeTestCases",
      "codebuild:DescribeCodeCoverages",
      "codecommit:GetBranch",
      "codecommit:GetCommit",
      "codecommit:GetRepository",
      "cloudwatch:GetMetricStatistics",
      "events:DescribeRule",
      "events:ListTargetsByRule",
      "events:ListRuleNamesByTarget",
    "logs:GetLogEvents"]
    resources = ["*"]
  }
  statement {
    sid    = "CodeStarConnectionsUserAccess"
    effect = "Allow"
    actions = [
      "codestar-connections:ListConnections",
      "codestar-connections:GetConnection"
    ]
    resources = ["arn:aws:codestar-connections:*:*:connection/*"]
  }
  statement {
    sid    = "CodeStarNotificationsPowerUserAccess"
    effect = "Allow"
    actions = [
      "codestar-notifications:DescribeNotificationRule"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "codestar-notifications:NotificationsForResource"
      values   = ["arn:aws:codebuild:*"]
    }
  }
  statement {
    sid    = "CodeStarNotificationsListAccess"
    effect = "Allow"
    actions = ["codestar-notifications:ListNotificationRules",
      "codestar-notifications:ListEventTypes",
    "codestar-notifications:ListTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "test" {
  name   = "test_cicd_user_policy"
  user   = aws_iam_user.test.name
  policy = data.aws_iam_policy_document.test.json
}