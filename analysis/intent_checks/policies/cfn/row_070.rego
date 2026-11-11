package intent.cfn.row_070

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pools": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": []
  },
  "cog_roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "lambda_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "lambda.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "sfn_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "^states\\."
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "attach": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": [
    {
     "path": [
      "Roles",
      "unauthenticated"
     ],
     "op": "present"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "two_pools",
   "kind": "exists",
   "tier": "core",
   "quote": "creates two Cognito identity pools",
   "select": "pools",
   "min": 2
  },
  {
   "id": "unauth_enabled",
   "kind": "attr",
   "tier": "core",
   "quote": "each with unauthenticated identities enabled",
   "select": "pools",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": true
   },
   "quantifier": "all"
  },
  {
   "id": "two_cognito_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role for each pool that can be assumed by unauthenticated Cognito identities",
   "select": "cog_roles",
   "min": 2
  },
  {
   "id": "unauth_condition",
   "kind": "exists",
   "tier": "detail",
   "quote": "can be assumed by unauthenticated Cognito identities",
   "min": 2,
   "justify": "one role per pool, two pools stated",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Federated",
       "*"
      ],
      "op": "eq",
      "value": "cognito-identity.amazonaws.com"
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Condition",
       "*",
       "cognito-identity.amazonaws.com:amr"
      ],
      "op": "none_eq",
      "value": "authenticated"
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Condition",
       "*",
       "cognito-identity.amazonaws.com:amr",
       "*"
      ],
      "op": "none_eq",
      "value": "authenticated"
     }
    ]
   }
  },
  {
   "id": "lambda_role_service",
   "kind": "exists",
   "tier": "core",
   "quote": "the Lambda-facing role also allowing Lambda service execution",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "lambda.amazonaws.com"
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Federated",
       "*"
      ],
      "op": "eq",
      "value": "cognito-identity.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "sfn_role_service",
   "kind": "exists",
   "tier": "core",
   "quote": "the Step Functions-facing role also allowing the Step Functions service to assume it",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Service",
       "*"
      ],
      "op": "regex",
      "value": "^states\\."
     },
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Federated",
       "*"
      ],
      "op": "eq",
      "value": "cognito-identity.amazonaws.com"
     }
    ]
   },
   "justify": "Step Functions service principal is states.<region>.amazonaws.com"
  },
  {
   "id": "attach_two",
   "kind": "exists",
   "tier": "core",
   "quote": "each role should be attached back to its corresponding identity pool as the unauthenticated role",
   "select": {
    "types": [
     "AWS::Cognito::IdentityPoolRoleAttachment"
    ],
    "where": [
     {
      "path": [
       "Roles",
       "unauthenticated"
      ],
      "op": "present"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "attach_refs",
   "kind": "exists",
   "tier": "core",
   "quote": "each role should be attached back to its corresponding identity pool",
   "select": "attach",
   "distinct_path": [
    "IdentityPoolId",
    "ref"
   ],
   "min": 2,
   "justify": "two pools, each with its own attachment"
  },
  {
   "id": "lambda_attach",
   "kind": "ref",
   "tier": "core",
   "quote": "one identity pool is used for Lambda-based access",
   "from": "attach",
   "to": "lambda_role"
  },
  {
   "id": "sfn_attach",
   "kind": "ref",
   "tier": "core",
   "quote": "the other is used for Step Functions workflow-based access",
   "from": "attach",
   "to": "sfn_role",
   "justify": "Step Functions service principal is states.<region>.amazonaws.com"
  },
  {
   "id": "lambda_invoke",
   "kind": "any_of",
   "tier": "core",
   "quote": "invoke Lambda functions",
   "justify": "invoking Lambda implies lambda:InvokeFunction",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lambda_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "lambda:InvokeFunction"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSLambda(_FullAccess|Role|FullAccess)"
     }
    }
   ]
  },
  {
   "id": "lambda_ddb",
   "kind": "any_of",
   "tier": "core",
   "quote": "work with DynamoDB and SES for the Lambda role",
   "justify": "any DynamoDB action counts as working with it",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lambda_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(dynamodb:.*|\\*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "op": "regex",
      "value": "(?i)^(dynamodb:.*|\\*)$"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDB"
     }
    }
   ]
  },
  {
   "id": "lambda_ses",
   "kind": "any_of",
   "tier": "core",
   "quote": "work with DynamoDB and SES for the Lambda role",
   "justify": "any SES action counts as working with it",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "lambda_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(ses:.*|\\*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "op": "regex",
      "value": "(?i)^(ses:.*|\\*)$"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSES"
     }
    }
   ]
  },
  {
   "id": "sfn_invoke",
   "kind": "any_of",
   "tier": "core",
   "quote": "invoke Lambda functions for the Step Functions role",
   "justify": "invoking Lambda implies lambda:InvokeFunction",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "sfn_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "lambda:InvokeFunction"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sfn_role",
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
      "op": "glob_covers",
      "value": "lambda:InvokeFunction"
     }
    },
    {
     "kind": "attr",
     "select": "sfn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSLambda(_FullAccess|Role|FullAccess)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
