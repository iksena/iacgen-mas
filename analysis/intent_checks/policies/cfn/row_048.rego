package intent.cfn.row_048

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "secret": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "iam": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
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
     "op": "regex",
     "value": "lambda\\.amazonaws\\.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "ssm_params",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a few parameters in the AWS Systems Manager Parameter Store",
   "justify": "'a few' means at least two",
   "select": "ssm",
   "min": 2
  },
  {
   "id": "secret",
   "kind": "exists",
   "tier": "core",
   "quote": "a secret in Secrets Manager",
   "select": "secret"
  },
  {
   "id": "secret_generated",
   "kind": "attr",
   "tier": "core",
   "quote": "with a dynamically generated password",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString"
    ],
    "op": "present"
   }
  },
  {
   "id": "lambda",
   "kind": "exists",
   "tier": "core",
   "quote": "a Lambda function",
   "select": "fn"
  },
  {
   "id": "lambda_name",
   "kind": "attr",
   "tier": "core",
   "quote": "the Lambda should be named ParameterStoreDemo",
   "select": "fn",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "eq",
    "value": "ParameterStoreDemo"
   }
  },
  {
   "id": "lambda_runtime",
   "kind": "attr",
   "tier": "core",
   "quote": "use Python 3.12",
   "justify": "Python 3.12 is runtime python3.12",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.12"
   }
  },
  {
   "id": "lambda_env",
   "kind": "all_of",
   "tier": "detail",
   "quote": "read the stack name from an environment variable",
   "justify": "the AWS::StackName pseudo-parameter resolves to stack in the normalised input, so either the variable's key or its value names the stack; os.environ/getenv is how Python reads it",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Environment",
       "Variables"
      ],
      "op": "regex",
      "value": "(?i)stack"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "os\\.(environ|getenv)"
     }
    }
   ]
  },
  {
   "id": "lambda_reads_ssm",
   "kind": "attr",
   "tier": "detail",
   "quote": "retrieves and prints all parameters under the stack's path",
   "justify": "all parameters under a path is GetParametersByPath, or DescribeParameters then a get; print or a logger is how it prints",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?is)(get_parameters_by_path|describe_parameters).*(print\\(|logger\\.|logging\\.)"
   }
  },
  {
   "id": "lambda_reads_secrets",
   "kind": "attr",
   "tier": "detail",
   "quote": "all secrets matching that prefix",
   "justify": "listing secrets by prefix is ListSecrets or BatchGetSecretValue with a name filter; print or a logger is how it prints",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?is)(list_secrets|batch_get_secret_value).*(print\\(|logger\\.|logging\\.)"
   }
  },
  {
   "id": "lambda_role",
   "kind": "exists",
   "tier": "core",
   "quote": "include the necessary IAM role",
   "select": "role"
  },
  {
   "id": "lambda_uses_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "include the necessary IAM role",
   "from": "fn",
   "to": "role"
  },
  {
   "id": "role_trust_lambda",
   "kind": "ref",
   "tier": "detail",
   "quote": "include the necessary IAM role",
   "justify": "the Lambda's execution role trusts lambda.amazonaws.com",
   "from": "fn",
   "to": "lambda_role"
  },
  {
   "id": "perm_ssm",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions to access the parameters",
   "justify": "reading parameters needs an ssm:Get* action, a wider ssm or * grant, or a managed policy that includes it",
   "checks": [
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(ssm:(get[a-z*]*|\\*)|\\*)$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(AmazonSSM(ReadOnly|Full)Access|AdministratorAccess)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(ssm:(get[a-z*]*|\\*)|\\*)$"
         }
        ]
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "perm_secrets",
   "kind": "any_of",
   "tier": "core",
   "quote": "and secrets",
   "justify": "reading secrets needs a secretsmanager get or list action, a wider secretsmanager or * grant, or a managed policy that includes it",
   "checks": [
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(secretsmanager:(get[a-z*]*|list[a-z*]*|\\*)|\\*)$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "(?i)(SecretsManagerReadWrite|AdministratorAccess)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
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
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(secretsmanager:(get[a-z*]*|list[a-z*]*|\\*)|\\*)$"
         }
        ]
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "x_param_type",
   "kind": "attr",
   "tier": "extra",
   "select": "ssm",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "String"
   }
  },
  {
   "id": "x_logs",
   "kind": "attr",
   "tier": "extra",
   "select": "iam",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(logs:(putlogevents|\\*)|AWSLambdaBasicExecutionRole)"
   }
  },
  {
   "id": "x_secret_template",
   "kind": "attr",
   "tier": "extra",
   "select": "secret",
   "cond": {
    "path": [
     "GenerateSecretString",
     "GenerateStringKey"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
