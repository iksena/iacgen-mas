package intent.tf.row_174

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "config_variable",
   "kind": "exists",
   "tier": "core",
   "quote": "parsing a YAML configuration file specified by the config variable",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "config"
     }
    ]
   }
  },
  {
   "id": "artifact_and_cache_buckets",
   "kind": "exists",
   "tier": "core",
   "min": 2,
   "quote": "dynamically provision S3 artifact and build cache buckets",
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
      "value": "aws_s3_bucket"
     }
    ]
   },
   "justify": "'S3 artifact and build cache buckets' -> two aws_s3_bucket resources"
  },
  {
   "id": "default_pipeline_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "an optional default CodePipeline IAM role under path \"/terraforest/\"",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "path"
        ],
        "op": "eq",
        "value": "/terraforest/"
       },
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "codepipeline.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
         "path"
        ],
        "op": "contains",
        "value": "/terraforest/"
       }
      ]
     }
    }
   ],
   "justify": "'CodePipeline IAM role' -> aws_iam_role trusted by codepipeline.amazonaws.com"
  },
  {
   "id": "default_pipeline_role_permissions",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting CodeCommit, CodeBuild, and ECR access",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "path"
        ],
        "op": "eq",
        "value": "/terraforest/"
       },
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "contains",
        "value": "codecommit:"
       },
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "contains",
        "value": "codebuild:"
       },
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "contains",
        "value": "ecr:"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "codecommit:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "codebuild:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ecr:"
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
         "path"
        ],
        "op": "eq",
        "value": "/terraforest/"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "codecommit:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "codebuild:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ecr:"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)codecommit:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)codebuild:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecr:"
       }
      ]
     }
    }
   ],
   "justify": "'CodeCommit, CodeBuild, and ECR access' -> codecommit:/codebuild:/ecr: actions"
  },
  {
   "id": "codestar_connections",
   "kind": "exists",
   "tier": "core",
   "quote": "CodeStar connections for Bitbucket, GitHub, or GitHub Enterprise Server source providers",
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
      "value": "aws_codestarconnections_connection"
     }
    ]
   },
   "justify": "'CodeStar connections' -> aws_codestarconnections_connection"
  },
  {
   "id": "pipelines_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "Pipelines must be configured with dynamic stages",
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
      "value": "aws_codepipeline"
     }
    ]
   },
   "justify": "'Pipelines' -> aws_codepipeline"
  },
  {
   "id": "event_rules_and_targets",
   "kind": "all_of",
   "tier": "core",
   "quote": "configure EventBridge event rules and targets",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_cloudwatch_event_rule"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_cloudwatch_event_target"
       }
      ]
     }
    }
   ],
   "justify": "'EventBridge event rules and targets' -> aws_cloudwatch_event_rule / _target"
  },
  {
   "id": "event_role_name_prefix",
   "kind": "any_of",
   "tier": "core",
   "quote": "custom IAM roles named by prefixing \"terrabits-\" to each pipeline's name",
   "justify": "'custom IAM roles' -> aws_iam_role named (name or name_prefix) with the stated prefix",
   "checks": [
    {
     "kind": "exists",
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
        "op": "contains",
        "value": "terrabits-"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
         "name_prefix"
        ],
        "op": "contains",
        "value": "terrabits-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "event_role_start_pipeline",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing codepipeline:StartPipelineExecution",
   "checks": [
    {
     "kind": "exists",
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "codepipeline:StartPipelineExecution"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "codepipeline:StartPipelineExecution"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
         "inline_policy"
        ],
        "op": "contains",
        "value": "codepipeline:StartPipelineExecution"
       }
      ]
     }
    }
   ],
   "justify": "IAM policy resource types carrying the stated codepipeline:StartPipelineExecution action"
  },
  {
   "id": "event_target_wiring",
   "kind": "exists",
   "tier": "detail",
   "quote": "to trigger pipelines",
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
      "value": "aws_cloudwatch_event_target"
     },
     {
      "path": [
       "properties",
       "arn"
      ],
      "op": "contains",
      "value": "aws_codepipeline"
     },
     {
      "path": [
       "properties",
       "role_arn"
      ],
      "op": "contains",
      "value": "aws_iam_role"
     }
    ]
   },
   "justify": "targets 'trigger pipelines' via the event IAM roles"
  },
  {
   "id": "trigger_cron",
   "kind": "exists",
   "tier": "detail",
   "quote": "cron schedule expressions",
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
      "value": "aws_cloudwatch_event_rule"
     },
     {
      "path": [
       "properties",
       "schedule_expression"
      ],
      "op": "present"
     }
    ]
   },
   "justify": "'cron schedule expressions' -> a rule with schedule_expression"
  },
  {
   "id": "trigger_custom_pattern",
   "kind": "exists",
   "tier": "detail",
   "quote": "custom EventBridge event patterns",
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
      "value": "aws_cloudwatch_event_rule"
     },
     {
      "path": [
       "properties",
       "event_pattern"
      ],
      "op": "present"
     },
     {
      "path": [
       "properties",
       "event_pattern"
      ],
      "op": "regex",
      "value": "^\\[?\"?\\$\\{"
     }
    ]
   },
   "justify": "'custom EventBridge event patterns' -> a rule whose event_pattern is supplied by configuration (an expression)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
