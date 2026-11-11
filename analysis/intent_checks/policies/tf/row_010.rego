package intent.tf.row_010

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "repo_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "reactjs-app-repo"
     }
    ]
   },
   "quote": "an Amazon ECR repository named \"reactjs-app-repo\""
  },
  {
   "id": "repo_immutable",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_ecr_repository"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "reactjs-app-repo"
     }
    ]
   },
   "cond": {
    "path": [
     "image_tag_mutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   },
   "quote": "immutable image tags"
  },
  {
   "id": "repo_scan_on_push",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_repository"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "reactjs-app-repo"
       }
      ]
     },
     "cond": {
      "path": [
       "image_scanning_configuration",
       "*",
       "scan_on_push"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ecr_registry_scanning_configuration"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rule",
       "*",
       "scan_frequency"
      ],
      "op": "eq",
      "value": "SCAN_ON_PUSH"
     }
    }
   ],
   "quote": "automatic scanning on push"
  },
  {
   "id": "role_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecsTaskExecutionRole"
     }
    ]
   },
   "quote": "an IAM role named \"ecsTaskExecutionRole\""
  },
  {
   "id": "role_assumed_by_ecs",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskExecutionRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?s)\"Action\":\\[?(\"[^\"]*\",)*\"sts:(AssumeRole|\\*)\"(,\"[^\"]*\")*\\]?,(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\",\"Principal\":\\{(?:\"AWS\":(?:\"[^\"]*\"|\\[[^\\]]*\\]),)?\"Service\":\\[?(\"[^\"]*\",)*\"ecs-tasks\\.amazonaws\\.com\""
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskExecutionRole"
       }
      ]
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
          "value": "ecs-tasks.amazonaws.com"
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
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskExecutionRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)ecs-tasks\\.amazonaws\\.com"
     }
    }
   ],
   "quote": "allows ECS tasks to assume it"
  },
  {
   "id": "role_policy_attached",
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
        "value": "AmazonECSTaskExecutionRolePolicy"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskExecutionRole"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskExecutionRole"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonECSTaskExecutionRolePolicy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonECSTaskExecutionRolePolicy"
       }
      ]
     },
     "cond": {
      "path": [
       "role"
      ],
      "op": "eq",
      "value": "ecsTaskExecutionRole"
     }
    }
   ],
   "quote": "attached with the AWS-managed AmazonECSTaskExecutionRolePolicy"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
