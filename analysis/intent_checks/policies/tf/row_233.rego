package intent.tf.row_233

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "cost_user",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)cost"
     }
    ]
   },
   "quote": "a mandatory cost reporting user"
  },
  {
   "id": "cost_user_env_suffix",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)cost.*dev$"
       }
      ]
     }
    }
   ],
   "quote": "a mandatory cost reporting user named with an environment suffix defaulting to \"dev\"",
   "justify": "default environment suffix dev"
  },
  {
   "id": "env_default",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "dev"
     }
    ]
   },
   "quote": "an environment suffix defaulting to \"dev\""
  },
  {
   "id": "cost_user_example_name",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)cost"
     }
    ]
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "mattermost-cost-report-dev"
   },
   "quote": "(such as \"mattermost-cost-report-dev\")"
  },
  {
   "id": "cost_policy_ce",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy allowing all Cost Explorer actions across all resources",
   "justify": "all Cost Explorer actions is ce:*"
  },
  {
   "id": "cost_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "regex",
        "value": "(?i)cost"
       }
      ]
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
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "regex",
        "value": "(?i)cost"
       }
      ]
     },
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "regex",
        "value": "(?i)cost"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
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
         "aws_iam_user_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)cost"
       }
      ]
     }
    }
   ],
   "quote": "a mandatory cost reporting user named with an environment suffix defaulting to \"dev\" (such as \"mattermost-cost-report-dev\") attached to an inline policy allowing all Cost Explorer actions"
  },
  {
   "id": "cost_policy_all_resources",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)Resource[\"\\']?\\s*[:=]\\s*(\\[\\s*)?[\"\\']\\*[\"\\']|resources:\\[\\*\\]"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(^|[^a-z0-9-])ce:\\*"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Resource[\"\\']?\\s*[:=]\\s*(\\[\\s*)?[\"\\']\\*[\"\\']|resources:\\[\\*\\]"
       }
      ]
     }
    }
   ],
   "quote": "across all resources"
  },
  {
   "id": "users_four",
   "kind": "exists",
   "tier": "core",
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
      "value": "aws_iam_user"
     }
    ]
   },
   "quote": "three optional IAM users",
   "min": 4,
   "justify": "one mandatory plus three optional users"
  },
  {
   "id": "optional_users_gated",
   "kind": "exists",
   "tier": "core",
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
      "value": "aws_iam_user"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditional creation toggles for three optional IAM users",
   "min": 3
  },
  {
   "id": "x_optional_users_off_by_default",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "max": 1
  },
  {
   "id": "db_rds",
   "kind": "any_of",
   "tier": "core",
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "rds:\\*"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "kms:\\*"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)rds:\\*"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)kms:\\*"
       }
      ]
     }
    }
   ],
   "quote": "a database disaster recovery user with full access to RDS and KMS",
   "justify": "full access means rds:* and kms:*"
  },
  {
   "id": "db_secrets",
   "kind": "any_of",
   "tier": "core",
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "rds:\\*"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)rds:\\*"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager"
       }
      ]
     }
    }
   ],
   "quote": "Secrets Manager access"
  },
  {
   "id": "exports_list_bucket",
   "kind": "any_of",
   "tier": "core",
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       }
      ]
     }
    }
   ],
   "quote": "bucket listing"
  },
  {
   "id": "exports_read",
   "kind": "any_of",
   "tier": "core",
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:GetObject"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:GetObject"
       }
      ]
     }
    }
   ],
   "quote": "object read/write permissions"
  },
  {
   "id": "exports_write",
   "kind": "any_of",
   "tier": "core",
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:PutObject"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:ListBucket"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:PutObject"
       }
      ]
     }
    }
   ],
   "quote": "object read/write permissions"
  },
  {
   "id": "packer_ec2",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ec2:(Run\\w*|\\*|Create\\w*)"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(Run\\w*|\\*|Create\\w*)"
       }
      ]
     }
    }
   ],
   "quote": "extensive permissions across EC2, Auto Scaling, CloudWatch Events, SSM parameters",
   "justify": "EC2 permissions"
  },
  {
   "id": "packer_autoscaling",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:(Describe|Update|\\*)"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:(Describe|Update|\\*)"
       }
      ]
     }
    }
   ],
   "quote": "extensive permissions across EC2, Auto Scaling, CloudWatch Events, SSM parameters"
  },
  {
   "id": "packer_events",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)events:"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)events:"
       }
      ]
     }
    }
   ],
   "quote": "extensive permissions across EC2, Auto Scaling, CloudWatch Events, SSM parameters"
  },
  {
   "id": "packer_ssm",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ssm:"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ssm:"
       }
      ]
     }
    }
   ],
   "quote": "extensive permissions across EC2, Auto Scaling, CloudWatch Events, SSM parameters"
  },
  {
   "id": "packer_iam_inspect",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(GetRole|GetInstanceProfile|\\*)"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(GetRole|GetInstanceProfile|\\*)"
       }
      ]
     }
    }
   ],
   "quote": "IAM profile/role inspections",
   "justify": "IAM inspection is Get actions on roles/instance profiles"
  },
  {
   "id": "packer_s3_state",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(GetObject|PutObject|\\*)"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(GetObject|PutObject|\\*)"
       }
      ]
     }
    }
   ],
   "quote": "S3 monitoring state bucket access"
  },
  {
   "id": "packer_lambda_config",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)lambda:((Get|Update)FunctionConfiguration|\\*)"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)lambda:((Get|Update)FunctionConfiguration|\\*)"
       }
      ]
     }
    }
   ],
   "quote": "specific Lambda function configuration permissions for a \"bind-server-network-attachment\" function"
  },
  {
   "id": "packer_lambda_function",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)bind[-_]server[-_]network[-_]attachment"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)bind[-_]server[-_]network[-_]attachment"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "bind-server-network-attachment"
       }
      ]
     }
    }
   ],
   "quote": "a \"bind-server-network-attachment\" function"
  },
  {
   "id": "packer_passrole",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:PassRole"
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
         "aws_iam_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)autoscaling:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:PassRole"
       }
      ]
     }
    }
   ],
   "quote": "pass-role authority for a dedicated server role"
  },
  {
   "id": "packer_region_account",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "data.aws_caller_identity"
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
        "value": "data.aws_region"
       }
      ]
     }
    }
   ],
   "quote": "in the current region and account"
  },
  {
   "id": "x_users_have_path",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_iam_user_policy_attachment"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "min": 3
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
