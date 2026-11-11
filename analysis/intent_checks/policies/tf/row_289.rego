package intent.tf.row_289

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ecs": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecs-role"
    }
   ]
  },
  "tasks": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecs-tasks-role"
    }
   ]
  },
  "events": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "events-role"
    }
   ]
  },
  "pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecs-policy"
    }
   ]
  },
  "roles": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ecs_role",
   "tier": "core",
   "quote": "an ECS service role named \"ecs-role\"",
   "kind": "exists",
   "select": "ecs"
  },
  {
   "id": "ecs_role_trust",
   "tier": "core",
   "quote": "trusted by ecs.amazonaws.com",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ecs",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "ecs\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "ecs",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ecs\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       }
      ]
     }
    }
   ],
   "justify": "trusted by a service means a trust policy allowing that service sts:AssumeRole"
  },
  {
   "id": "ecs_role_managed_policy",
   "tier": "core",
   "quote": "with the AWS managed AmazonEC2ContainerServiceRole policy attached",
   "kind": "any_of",
   "checks": [
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
     "to": "ecs"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
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
     "to": "ecs"
    },
    {
     "kind": "attr",
     "select": "ecs",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "/AmazonEC2ContainerServiceRole$"
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonEC2ContainerServiceRole$"
       }
      ]
     },
     "to": "ecs"
    }
   ]
  },
  {
   "id": "tasks_role",
   "tier": "core",
   "quote": "an ECS task execution role named \"ecs-tasks-role\"",
   "kind": "exists",
   "select": "tasks"
  },
  {
   "id": "tasks_role_trust",
   "tier": "core",
   "quote": "trusted by ecs-tasks.amazonaws.com",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "ecs-tasks\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "tasks",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ecs-tasks\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       }
      ]
     }
    }
   ],
   "justify": "trusted by a service means a trust policy allowing that service sts:AssumeRole"
  },
  {
   "id": "tasks_role_managed_policy",
   "tier": "core",
   "quote": "with the AWS managed AmazonECSTaskExecutionRolePolicy attached",
   "kind": "any_of",
   "checks": [
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
     "to": "tasks"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
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
     "to": "tasks"
    },
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "/AmazonECSTaskExecutionRolePolicy$"
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "regex",
        "value": "/AmazonECSTaskExecutionRolePolicy$"
       }
      ]
     },
     "to": "tasks"
    }
   ]
  },
  {
   "id": "events_role",
   "tier": "core",
   "quote": "an EventBridge role named \"events-role\"",
   "kind": "exists",
   "select": "events"
  },
  {
   "id": "events_role_trust",
   "tier": "core",
   "quote": "trusted by events.amazonaws.com",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "events",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "events\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "events",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "events\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       }
      ]
     }
    }
   ],
   "justify": "trusted by a service means a trust policy allowing that service sts:AssumeRole"
  },
  {
   "id": "events_policy_named",
   "tier": "core",
   "quote": "a customer managed policy named \"ecs-policy\"",
   "kind": "exists",
   "select": "pol"
  },
  {
   "id": "events_policy_attached",
   "tier": "core",
   "quote": "The EventBridge role must get a customer managed policy",
   "kind": "any_of",
   "checks": [
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
        "op": "eq",
        "value": "events-role"
       }
      ]
     },
     "to": "pol"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "events-role"
       }
      ]
     },
     "to": "pol"
    },
    {
     "kind": "ref",
     "from": "events",
     "to": "pol"
    }
   ]
  },
  {
   "id": "policy_run_tasks",
   "tier": "core",
   "quote": "a customer managed policy named \"ecs-policy\" that allows running ECS tasks",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "pol",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecs:RunTask"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ecs:(RunTask|\\*)"
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
         "name"
        ],
        "op": "eq",
        "value": "ecs-policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?i)ecs:(RunTask|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_pass_task_role",
   "tier": "core",
   "quote": "passing only the task execution role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "iam:PassRole"
         },
         {
          "path": [
           "resources",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         }
        ]
       }
      ]
     },
     "to": "tasks"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ecs-policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "tasks"
    },
    {
     "kind": "exists",
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
        "value": "ecs-policy"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:PassRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "role/ecs-tasks-role"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "events_role_cloudwatch_logs",
   "tier": "core",
   "quote": "also the AWS managed CloudWatchLogsFullAccess policy",
   "kind": "any_of",
   "checks": [
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
        "value": "/CloudWatchLogsFullAccess$"
       }
      ]
     },
     "to": "events"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "/CloudWatchLogsFullAccess$"
       }
      ]
     },
     "to": "events"
    },
    {
     "kind": "attr",
     "select": "events",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "/CloudWatchLogsFullAccess$"
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "regex",
        "value": "/CloudWatchLogsFullAccess$"
       }
      ]
     },
     "to": "events"
    }
   ]
  },
  {
   "id": "force_detach",
   "tier": "detail",
   "quote": "All roles should force-detach policies on deletion",
   "kind": "attr",
   "select": "roles",
   "cond": {
    "path": [
     "force_detach_policies"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "role_path",
   "tier": "detail",
   "quote": "use the \"/\" path",
   "kind": "attr",
   "select": "roles",
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quantifier": "all"
  },
  {
   "id": "optional_tags_default_tags",
   "tier": "detail",
   "quote": "accept optional tags that skip any tag already set identically in the provider default tags",
   "kind": "any_of",
   "checks": [
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
       "data.aws_default_tags"
      ],
      "where": []
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
        "value": "data.aws_default_tags"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "optional_tags_input",
   "tier": "detail",
   "quote": "accept optional tags",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)tags"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": null
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)tags"
       },
       {
        "path": [
         "default"
        ],
        "op": "len_eq",
        "value": 0
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_effect_allow",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "data.aws_iam_policy_document"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "statement",
     "*",
     "effect"
    ],
    "op": "eq",
    "value": "Allow"
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
