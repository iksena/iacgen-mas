# Glue Service Role
resource "aws_iam_role" "glue_service_role" {
  name = "glue-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "glue.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy_attachment" "glue_service_role_policy" {
  name       = "glue-service-role-policy"
  roles       = [aws_iam_role.glue_service_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3_access_policy" {
  name = "GlueS3AccessPolicy"
  role = aws_iam_role.glue_service_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::nlp-pipeline-bucket/*"
      }
    ]
  })
}

# Comprehend Service Role
resource "aws_iam_role" "comprehend_service_role" {
  name = "comprehend-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "comprehend.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "comprehend_s3_access_policy" {
  name = "ComprehendS3AccessPolicy"
  role = aws_iam_role.comprehend_service_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::nlp-pipeline-bucket/*"
      }
    ]
  })
}

# Lambda Execution Role
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda-basic-execution"
  roles       = [aws_iam_role.lambda_execution_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_custom_policy" {
  name = "LambdaCustomPolicy"
  role = aws_iam_role.lambda_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem",
          "stepfunctions:StartExecution"
        ]
        Resource = [
          "arn:aws:s3:::nlp-pipeline-bucket/*",
          "arn:aws:dynamodb:${var.aws_region}:${var.aws_account_id}:table/NLPResults",
          "arn:aws:states:${var.aws_region}:${var.aws_account_id}:stateMachine:YourStateMachineName"
        ]
      }
    ]
  })
}

# Step Functions Service Role
resource "aws_iam_role" "step_functions_service_role" {
  name = "step-functions-service-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "states.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "step_functions_policy" {
  name = "StepFunctionsPolicy"
  role = aws_iam_role.step_functions_service_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "glue:StartJobRun"
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:*",
          "arn:aws:glue:${var.aws_region}:${var.aws_account_id}:job/*"
        ]
      }
    ]
  })
}