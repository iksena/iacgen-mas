package intent.tf.row_173

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pp": {
   "types": [
    "aws_iam_account_password_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "pp_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "account-wide IAM password policy",
   "select": "pp"
  },
  {
   "id": "pp_min_length",
   "kind": "attr",
   "tier": "core",
   "quote": "a minimum length of 14 characters",
   "select": "pp",
   "cond": {
    "path": [
     "minimum_password_length"
    ],
    "op": "eq",
    "value": 14
   }
  },
  {
   "id": "pp_lower",
   "kind": "attr",
   "tier": "core",
   "quote": "lowercase",
   "select": "pp",
   "cond": {
    "path": [
     "require_lowercase_characters"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pp_upper",
   "kind": "attr",
   "tier": "core",
   "quote": "uppercase",
   "select": "pp",
   "cond": {
    "path": [
     "require_uppercase_characters"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pp_numbers",
   "kind": "attr",
   "tier": "core",
   "quote": "numeric characters",
   "select": "pp",
   "cond": {
    "path": [
     "require_numbers"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pp_allow_change",
   "kind": "attr",
   "tier": "core",
   "quote": "allowing users to change their own password",
   "select": "pp",
   "cond": {
    "path": [
     "allow_users_to_change_password"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pp_max_age",
   "kind": "attr",
   "tier": "core",
   "quote": "a maximum password age of 90 days",
   "select": "pp",
   "cond": {
    "path": [
     "max_password_age"
    ],
    "op": "eq",
    "value": 90
   }
  },
  {
   "id": "pp_reuse",
   "kind": "attr",
   "tier": "core",
   "quote": "preventing reuse of the last 3 passwords",
   "select": "pp",
   "cond": {
    "path": [
     "password_reuse_prevention"
    ],
    "op": "eq",
    "value": 3
   }
  },
  {
   "id": "pp_no_symbols",
   "kind": "attr",
   "tier": "core",
   "quote": "while not requiring symbols",
   "select": "pp",
   "cond": {
    "path": [
     "require_symbols"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "env_name_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "an environment name variable defaulting to \"dev\"",
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
   }
  },
  {
   "id": "role_task_name",
   "kind": "attr",
   "tier": "core",
   "quote": "an ECS task role named by prefixing \"ecs-task-role-for-\" with the environment name value",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "ecs-task-role-for-dev"
   },
   "justify": "default environment name is dev"
  },
  {
   "id": "role_exec_name",
   "kind": "attr",
   "tier": "core",
   "quote": "an ECS execution role named by prefixing \"ecs-execution-role-for-\" with the environment name value",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "ecs-execution-role-for-dev"
   },
   "justify": "default environment name is dev"
  },
  {
   "id": "role_events_name",
   "kind": "attr",
   "tier": "core",
   "quote": "an EventBridge-assumable ECS events role named by prefixing \"ecs_events_role-for-\" with the environment name value",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "ecs_events_role-for-dev"
   },
   "justify": "default environment name is dev"
  },
  {
   "id": "role_events_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing events.amazonaws.com to assume it",
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
        "op": "regex",
        "value": "^ecs_events_role-for-"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)events[.]amazonaws[.]com"
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
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "ecs_events_role-for-"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)events[.]amazonaws[.]com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "task_secrets_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the managed SecretsManagerReadWrite and AmazonS3FullAccess policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "SecretsManagerReadWrite"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/SecretsManagerReadWrite"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/SecretsManagerReadWrite$"
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/SecretsManagerReadWrite$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "task_s3_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the managed SecretsManagerReadWrite and AmazonS3FullAccess policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AmazonS3FullAccess"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/AmazonS3FullAccess"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonS3FullAccess$"
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonS3FullAccess$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "task_ssm_inline",
   "kind": "any_of",
   "tier": "core",
   "quote": "plus an inline policy permitting SSM messages channel actions",
   "checks": [
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
        "op": "regex",
        "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-task-role-for-"
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
        "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
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
        "op": "regex",
        "value": "^ecs-task-role-for-"
       }
      ]
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)ssmmessages:(Create|Open)?(Control|Data)?Channel|ssmmessages:[*]"
     }
    }
   ]
  },
  {
   "id": "exec_ecs_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the managed AmazonECSTaskExecutionRolePolicy and AmazonEC2ContainerServiceRole policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AmazonECSTaskExecutionRolePolicy"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy$"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "exec_ec2_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the managed AmazonECSTaskExecutionRolePolicy and AmazonEC2ContainerServiceRole policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AmazonEC2ContainerServiceRole"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole$"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "exec_secrets_inline",
   "kind": "any_of",
   "tier": "core",
   "quote": "plus an inline policy permitting Secrets Manager reads",
   "checks": [
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
        "op": "regex",
        "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)secretsmanager:(GetSecretValue|Get[*]|[*])"
     }
    }
   ]
  },
  {
   "id": "exec_kms_inline",
   "kind": "any_of",
   "tier": "core",
   "quote": "and KMS decryption",
   "checks": [
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
        "op": "regex",
        "value": "(?i)kms:(Decrypt|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)kms:(Decrypt|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)kms:(Decrypt|[*])"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)kms:(Decrypt|[*])"
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
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs-execution-role-for-"
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
        "value": "(?i)kms:(Decrypt|[*])"
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
        "op": "regex",
        "value": "^ecs-execution-role-for-"
       }
      ]
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)kms:(Decrypt|[*])"
     }
    }
   ]
  },
  {
   "id": "events_ecs_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the same execution-role managed policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AmazonECSTaskExecutionRolePolicy"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy$"
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
        "op": "regex",
        "value": "^ecs_events_role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "events_ec2_managed",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the same execution-role managed policies",
   "checks": [
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AmazonEC2ContainerServiceRole"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
       },
       {
        "path": [
         "properties",
         "managed_policy_arns"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole"
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
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole$"
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
        "op": "regex",
        "value": "^ecs_events_role-for-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole$"
       },
       {
        "path": [
         "role"
        ],
        "op": "regex",
        "value": "^ecs_events_role-for-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lambda_two_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "a \"public\" Lambda role with basic CloudWatch logging permissions; a \"VPC\" Lambda role",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)lambda[.]amazonaws[.]com"
     }
    ]
   },
   "min": 2,
   "justify": "a public and a VPC Lambda role are two roles"
  },
  {
   "id": "lambda_logs",
   "kind": "any_of",
   "tier": "core",
   "quote": "basic CloudWatch logging permissions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogGroup|CreateLogStream|PutLogEvents|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)logs:(CreateLogGroup|CreateLogStream|PutLogEvents|[*])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AWSLambda(Basic|VPCAccess)ExecutionRole"
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
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "/AWSLambda(Basic|VPCAccess)ExecutionRole"
     }
    }
   ]
  },
  {
   "id": "lambda_vpc_eni_create",
   "kind": "any_of",
   "tier": "core",
   "quote": "EC2 network interface creation, deletion, and description",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(CreateNetworkInterface|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(CreateNetworkInterface|[*])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AWSLambdaVPCAccessExecutionRole"
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
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "/AWSLambdaVPCAccessExecutionRole"
     }
    }
   ]
  },
  {
   "id": "lambda_vpc_eni_delete",
   "kind": "any_of",
   "tier": "core",
   "quote": "EC2 network interface creation, deletion, and description",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DeleteNetworkInterface|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DeleteNetworkInterface|[*])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AWSLambdaVPCAccessExecutionRole"
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
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "/AWSLambdaVPCAccessExecutionRole"
     }
    }
   ]
  },
  {
   "id": "lambda_vpc_eni_describe",
   "kind": "any_of",
   "tier": "core",
   "quote": "EC2 network interface creation, deletion, and description",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(DescribeNetworkInterfaces|Describe[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(DescribeNetworkInterfaces|Describe[*]|[*])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AWSLambdaVPCAccessExecutionRole"
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
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "/AWSLambdaVPCAccessExecutionRole"
     }
    }
   ]
  },
  {
   "id": "lambda_vpc_invoke",
   "kind": "any_of",
   "tier": "detail",
   "quote": "and Lambda function invocation",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(InvokeFunction|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)lambda:(InvokeFunction|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sfn_role_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "a Step Functions state machine role",
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
      "value": "(?i)states[.]amazonaws[.]com"
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
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)states[.]amazonaws[.]com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sfn_log_delivery",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting log delivery, resource policies",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogDelivery|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)logs:(CreateLogDelivery|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sfn_log_resource_policies",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permitting log delivery, resource policies",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:(PutResourcePolicy|DescribeResourcePolicies|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)logs:(PutResourcePolicy|DescribeResourcePolicies|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sfn_alarms",
   "kind": "any_of",
   "tier": "detail",
   "quote": "and CloudWatch alarm descriptions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(DescribeAlarms|Describe[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cloudwatch:(DescribeAlarms|Describe[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "eventbridge_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "an EventBridge execution role",
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
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "(?i)events[.]amazonaws[.]com"
       }
      ]
     },
     "min": 2
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)events[.]amazonaws[.]com|events_assume|assume_role_events"
       }
      ]
     },
     "min": 2
    }
   ],
   "justify": "the ECS events role plus the separate EventBridge execution role both trust EventBridge (two roles stated)"
  },
  {
   "id": "eventbridge_start_execution",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting Step Functions state machine execution",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)states:(StartExecution|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)states:(StartExecution|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "eventbridge_current_account",
   "kind": "any_of",
   "tier": "detail",
   "quote": "strictly targeting state machines in the current account",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "states:[a-z0-9-]*:[0-9]{12}:stateMachine|aws:ResourceAccount|aws:PrincipalAccount"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)caller_identity|AccountId|account_id|states:[a-z0-9-]*:[0-9]{12}:stateMachine|aws:ResourceAccount|aws:PrincipalAccount"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)states:StartExecution"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_policy_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "a \"developers-policy-limited-mfa\" policy",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "developers-policy-limited-mfa"
     }
    ]
   }
  },
  {
   "id": "dev_s3_get",
   "kind": "any_of",
   "tier": "detail",
   "quote": "S3 object read/write/delete and bucket listing access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(GetObject|Get[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(GetObject|Get[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_s3_put",
   "kind": "any_of",
   "tier": "detail",
   "quote": "S3 object read/write/delete and bucket listing access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(PutObject|Put[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(PutObject|Put[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_s3_delete",
   "kind": "any_of",
   "tier": "detail",
   "quote": "S3 object read/write/delete and bucket listing access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(DeleteObject|Delete[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(DeleteObject|Delete[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_s3_list",
   "kind": "any_of",
   "tier": "detail",
   "quote": "bucket listing access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(ListBucket|List[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(ListBucket|List[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_secrets_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-conditioned Secrets Manager read-only access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)secretsmanager:(Get[*]|GetSecretValue|List[*]|Describe[*]|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)secretsmanager:(Get[*]|GetSecretValue|List[*]|Describe[*]|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_mfa_condition",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-conditioned Secrets Manager read-only access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)MultiFactorAuthPresent"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)MultiFactorAuthPresent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_cloudwatch_read",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned CloudWatch and ECS read-only access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(logs|cloudwatch):"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(logs|cloudwatch):"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_ecs_read",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned CloudWatch and ECS read-only access",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecs:(Describe|List|Get)"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ecs:(Describe|List|Get)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_self_password",
   "kind": "any_of",
   "tier": "detail",
   "quote": "self-service IAM password, MFA, access key, and SSH key management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(ChangePassword|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(ChangePassword|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_self_mfa",
   "kind": "any_of",
   "tier": "detail",
   "quote": "self-service IAM password, MFA, access key, and SSH key management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:([A-Za-z]*MFADevice|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:([A-Za-z]*MFADevice|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_self_access_keys",
   "kind": "any_of",
   "tier": "detail",
   "quote": "self-service IAM password, MFA, access key, and SSH key management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:([A-Za-z]*AccessKey|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:([A-Za-z]*AccessKey|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_self_ssh",
   "kind": "any_of",
   "tier": "detail",
   "quote": "self-service IAM password, MFA, access key, and SSH key management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:([A-Za-z]*SSHPublicKey|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:([A-Za-z]*SSHPublicKey|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_mfa_deny",
   "kind": "any_of",
   "tier": "core",
   "quote": "an explicit MFA enforcement block denying unauthenticated actions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)Effect\\W{1,6}Deny"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "developers-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Effect\\W{1,6}Deny"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_policy_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "a \"billing-policy-limited-mfa\" policy",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "billing-policy-limited-mfa"
     }
    ]
   }
  },
  {
   "id": "bill_billing",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-conditioned access to billing, budgets, cost explorer, payments, and tax APIs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)billing:|aws-portal:"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)billing:|aws-portal:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_budgets",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned access to billing, budgets, cost explorer, payments, and tax APIs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)budgets:"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)budgets:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_cost_explorer",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned access to billing, budgets, cost explorer, payments, and tax APIs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ce:"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ce:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_payments",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned access to billing, budgets, cost explorer, payments, and tax APIs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)payments:|aws-portal:([A-Za-z]*Payment|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)payments:|aws-portal:([A-Za-z]*Payment|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_tax",
   "kind": "any_of",
   "tier": "detail",
   "quote": "MFA-conditioned access to billing, budgets, cost explorer, payments, and tax APIs",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)tax:|aws-portal:([A-Za-z]*Tax|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)tax:|aws-portal:([A-Za-z]*Tax|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_mfa_condition",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-conditioned access to billing",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)MultiFactorAuthPresent"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)MultiFactorAuthPresent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_self_mfa",
   "kind": "any_of",
   "tier": "detail",
   "quote": "alongside self-service MFA and password management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:([A-Za-z]*MFADevice|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:([A-Za-z]*MFADevice|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bill_self_password",
   "kind": "any_of",
   "tier": "detail",
   "quote": "alongside self-service MFA and password management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(ChangePassword|[*])"
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
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "billing-policy-limited-mfa"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(ChangePassword|[*])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_task_role_trust_session",
   "kind": "attr",
   "tier": "extra",
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
      "value": "ecs-task-role-for-dev"
     }
    ]
   },
   "cond": {
    "path": [
     "max_session_duration"
    ],
    "op": "eq",
    "value": 3600
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
