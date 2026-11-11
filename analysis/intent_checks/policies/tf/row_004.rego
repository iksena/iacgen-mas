package intent.tf.row_004

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lambda_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "regex",
     "value": "lambda\\.amazonaws\\.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_exists",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "creates an IAM execution role for an AWS Lambda function"
  },
  {
   "id": "role_assumed_by_lambda",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?s)\"Action\":\\[?(\"[^\"]*\",)*\"sts:(AssumeRole|\\*)\"(,\"[^\"]*\")*\\]?,(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\",\"Principal\":\\{(?:\"AWS\":(?:\"[^\"]*\"|\\[[^\\]]*\\]),)?\"Service\":\\[?(\"[^\"]*\",)*\"lambda\\.amazonaws\\.com\""
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sts:AssumeRole"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "lambda.amazonaws.com"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)lambda\\.amazonaws\\.com"
     }
    }
   ],
   "quote": "The role must allow the AWS Lambda service to assume it"
  },
  {
   "id": "attach_vpc_access",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSLambdaVPCAccessExecutionRole"
       }
      ]
     },
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWSLambdaVPCAccessExecutionRole"
     }
    }
   ],
   "quote": "AWSLambdaVPCAccessExecutionRole"
  },
  {
   "id": "attach_efs_client",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonElasticFileSystemClientFullAccess"
       }
      ]
     },
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonElasticFileSystemClientFullAccess"
     }
    }
   ],
   "quote": "AmazonElasticFileSystemClientFullAccess"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
