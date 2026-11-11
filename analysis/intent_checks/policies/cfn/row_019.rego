package intent.cfn.row_019

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "ro": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "sp": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "lambda_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "lambda.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "lambda_function",
   "kind": "exists",
   "select": "fn",
   "tier": "core",
   "quote": "creates an AWS Lambda function"
  },
  {
   "id": "iam_role",
   "kind": "exists",
   "select": "ro",
   "tier": "core",
   "quote": "an IAM role"
  },
  {
   "id": "ssm_parameter",
   "kind": "exists",
   "select": "sp",
   "tier": "core",
   "quote": "an SSM parameter"
  },
  {
   "id": "param_name",
   "kind": "attr",
   "select": "sp",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "dbUsername"
   },
   "tier": "core",
   "quote": "named \"dbUsername\""
  },
  {
   "id": "param_default_alice",
   "kind": "attr",
   "select": "sp",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "eq",
    "value": "alice"
   },
   "tier": "core",
   "quote": "defaults to \"alice\""
  },
  {
   "id": "param_overridable",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "alice"
   },
   "tier": "detail",
   "quote": "can be overridden at stack creation"
  },
  {
   "id": "lambda_python",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python3\\."
   },
   "tier": "core",
   "quote": "using Python 3.8",
   "justify": "python3.8 can no longer be created (cfn-lint E2533: creation disabled 2026-06-01), so the prompt's family is accepted"
  },
  {
   "id": "lambda_boto3_ssm",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?is)boto3.*ssm.*get_parameter"
   },
   "tier": "detail",
   "quote": "retrieve this username from SSM at runtime via the boto3 client"
  },
  {
   "id": "lambda_uses_role",
   "kind": "ref",
   "from": "fn",
   "to": "lambda_role",
   "tier": "core",
   "quote": "The IAM role must grant least-privilege permissions for the Lambda"
  },
  {
   "id": "role_trusts_lambda",
   "kind": "attr",
   "select": "ro",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "lambda.amazonaws.com"
   },
   "tier": "detail",
   "quote": "The IAM role must grant least-privilege permissions for the Lambda"
  },
  {
   "id": "role_reads_parameter",
   "kind": "any_of",
   "tier": "core",
   "quote": "grant least-privilege permissions for the Lambda to read the specific parameter",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ssm:GetParameter"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(ssm:(Get|Describe)|kms:Decrypt)",
        "every": true
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i):parameter/?(\\$\\{[^}]+\\}|[^*]*dbUsername)$",
        "every": true
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ssm:GetParameter"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(ssm:(Get|Describe)|kms:Decrypt)",
          "every": true
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "(?i):parameter/?(\\$\\{[^}]+\\}|[^*]*dbUsername)$",
          "every": true
         }
        ]
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "ssm:GetParameter"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(ssm:(Get|Describe)|kms:Decrypt)",
          "every": true
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "(?i):parameter/?(\\$\\{[^}]+\\}|[^*]*dbUsername)$",
          "every": true
         }
        ]
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    }
   ],
   "justify": "reading the specific parameter least-privilege implies only read actions on that parameter's ARN, by name or by reference"
  },
  {
   "id": "no_broad_ssm_grant",
   "kind": "all_of",
   "tier": "detail",
   "quote": "least-privilege permissions",
   "justify": "a wildcard grant on the role is not least privilege",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
     "quantifier": "all",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "none_eq",
      "value": "ssm:*"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "quantifier": "all",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "none_eq",
      "value": "*"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
