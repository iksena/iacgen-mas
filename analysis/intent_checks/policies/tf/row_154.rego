package intent.tf.row_154

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "svc": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecsServiceRole"
    }
   ]
  },
  "exec": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecsExecTaskRole"
    }
   ]
  },
  "task": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecsTaskRole"
    }
   ]
  },
  "asc": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecs_autoscale_role"
    }
   ]
  },
  "cd": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ecs_codedeploy_role"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_svc",
   "tier": "core",
   "kind": "exists",
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
      "value": "ecsServiceRole"
     }
    ]
   },
   "quote": "\"ecsServiceRole\""
  },
  {
   "id": "role_exec",
   "tier": "core",
   "kind": "exists",
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
      "value": "ecsExecTaskRole"
     }
    ]
   },
   "quote": "\"ecsExecTaskRole\""
  },
  {
   "id": "role_task",
   "tier": "core",
   "kind": "exists",
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
      "value": "ecsTaskRole"
     }
    ]
   },
   "quote": "\"ecsTaskRole\""
  },
  {
   "id": "role_asc",
   "tier": "core",
   "kind": "exists",
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
      "value": "ecs_autoscale_role"
     }
    ]
   },
   "quote": "\"ecs_autoscale_role\""
  },
  {
   "id": "role_cd",
   "tier": "core",
   "kind": "exists",
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
      "value": "ecs_codedeploy_role"
     }
    ]
   },
   "quote": "\"ecs_codedeploy_role\""
  },
  {
   "id": "svc_trust_ecs",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsServiceRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs.amazonaws.com"
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
        "value": "ecsServiceRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "svc",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "ecs.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecsServiceRole\" allowing ecs.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "svc_trust_s3",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsServiceRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
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
        "value": "ecsServiceRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "svc",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "s3.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecsServiceRole\" allowing ecs.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "exec_trust_tasks",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsExecTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs-tasks.amazonaws.com"
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
        "value": "ecsExecTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs-tasks.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "exec",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
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
    }
   ],
   "quote": "\"ecsExecTaskRole\" allowing ecs-tasks.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "exec_trust_s3",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsExecTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
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
        "value": "ecsExecTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "exec",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "s3.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecsExecTaskRole\" allowing ecs-tasks.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "task_trust_tasks",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs-tasks.amazonaws.com"
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
        "value": "ecsTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ecs-tasks.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "task",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
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
    }
   ],
   "quote": "\"ecsTaskRole\" allowing ecs-tasks.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "task_trust_s3",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecsTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
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
        "value": "ecsTaskRole"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "task",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "s3.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecsTaskRole\" allowing ecs-tasks.amazonaws.com and s3.amazonaws.com to assume it"
  },
  {
   "id": "asc_trust",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecs_autoscale_role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "application-autoscaling.amazonaws.com"
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
        "value": "ecs_autoscale_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "application-autoscaling.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "asc",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "application-autoscaling.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecs_autoscale_role\" allowing application-autoscaling.amazonaws.com to assume it"
  },
  {
   "id": "cd_trust",
   "tier": "core",
   "kind": "any_of",
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
        "value": "ecs_codedeploy_role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "codedeploy.amazonaws.com"
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
        "value": "ecs_codedeploy_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "codedeploy.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "cd",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "codedeploy.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "\"ecs_codedeploy_role\" allowing codedeploy.amazonaws.com to assume it"
  },
  {
   "id": "pol_ecsTaskRolePolicy",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRolePolicy"
       }
      ]
     },
     "to": "svc"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRolePolicy"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "svc",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRolePolicy"
       }
      ]
     },
     "to": "svc",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecsTaskRolePolicy"
     }
    }
   ],
   "quote": "attached to an inline policy \"ecsTaskRolePolicy\""
  },
  {
   "id": "pol_ecsExecRolePolicy",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecsExecRolePolicy"
       }
      ]
     },
     "to": "exec"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsExecRolePolicy"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "exec",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsExecRolePolicy"
       }
      ]
     },
     "to": "exec",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "exec",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecsExecRolePolicy"
     }
    }
   ],
   "quote": "attached to inline policies \"ecsExecRolePolicy\""
  },
  {
   "id": "pol_ecsExecution_additional",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecsExecution_additional"
       }
      ]
     },
     "to": "exec"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsExecution_additional"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "exec",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsExecution_additional"
       }
      ]
     },
     "to": "exec",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "exec",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecsExecution_additional"
     }
    }
   ],
   "quote": "\"ecsExecution_additional\""
  },
  {
   "id": "pol_ecsTaskRole_additional",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRole_additional"
       }
      ]
     },
     "to": "task"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRole_additional"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "task",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecsTaskRole_additional"
       }
      ]
     },
     "to": "task",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "task",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecsTaskRole_additional"
     }
    }
   ],
   "quote": "attached to an inline policy \"ecsTaskRole_additional\""
  },
  {
   "id": "pol_ecs_autoscale_role_policy",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_autoscale_role_policy"
       }
      ]
     },
     "to": "asc"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_autoscale_role_policy"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "asc",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_autoscale_role_policy"
       }
      ]
     },
     "to": "asc",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "asc",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecs_autoscale_role_policy"
     }
    }
   ],
   "quote": "attached to an inline policy \"ecs_autoscale_role_policy\""
  },
  {
   "id": "pol_ecs_codedeploy_role_policy",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy"
       }
      ]
     },
     "to": "cd"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "cd",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy"
       }
      ]
     },
     "to": "cd",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cd",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecs_codedeploy_role_policy"
     }
    }
   ],
   "quote": "inline policies \"ecs_codedeploy_role_policy\""
  },
  {
   "id": "pol_ecs_codedeploy_role_policy_task",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "to": "cd"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "cd",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "to": "cd",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cd",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecs_codedeploy_role_policy_task"
     }
    }
   ],
   "quote": "\"ecs_codedeploy_role_policy_task\""
  },
  {
   "id": "pol_ecs_codedeploy_role_policy_task_exec",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "to": "cd"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "from_path": [
      "role"
     ],
     "to": "cd",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "to": "cd",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "cd",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "ecs_codedeploy_role_policy_task_exec"
     }
    }
   ],
   "quote": "\"ecs_codedeploy_role_policy_task_exec\""
  },
  {
   "id": "svc_policy_perms",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)elasticloadbalancing:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ec2:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)secretsmanager:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)kms:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)codedeploy:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)sns:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cloudwatch:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)lambda:"
     }
    }
   ],
   "quote": "granting permissions for ELB, EC2, SSM, Secrets Manager, KMS, CodeDeploy, SNS, CloudWatch, and Lambda operations",
   "justify": "ELB maps to the elasticloadbalancing IAM prefix"
  },
  {
   "id": "exec_policy_perms",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecr:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(describeservices|describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)logs:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)secretsmanager:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)kms:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecRolePolicy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ssm:"
     }
    }
   ],
   "quote": "granting ECR, ECS service description, CloudWatch logging, Secrets Manager, KMS, and SSM permissions",
   "justify": "CloudWatch logging maps to the logs IAM prefix"
  },
  {
   "id": "perms_ecsExecution_additional",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecution_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(listservices|list\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecution_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(describeservices|describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecution_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:(getobject|get\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsExecution_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:(putobject|put\\*|\\*)"
     }
    }
   ],
   "quote": "granting ECS service listing and description plus S3 object read/write access",
   "justify": "object write means s3:PutObject"
  },
  {
   "id": "perms_ecsTaskRole_additional",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRole_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(listservices|list\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRole_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(describeservices|describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRole_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:(getobject|get\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecsTaskRole_additional\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:(putobject|put\\*|\\*)"
     }
    }
   ],
   "quote": "granting ECS service listing and description plus S3 object read/write access",
   "justify": "object write means s3:PutObject"
  },
  {
   "id": "asc_perms",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_autoscale_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(describeservices|describe\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_autoscale_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:(updateservice|update\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_autoscale_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cloudwatch:"
     }
    }
   ],
   "quote": "granting ECS service description and update access alongside CloudWatch alarm permissions"
  },
  {
   "id": "cd_managed",
   "tier": "core",
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
        "value": "AWSCodeDeployRole$"
       }
      ]
     },
     "to": "cd"
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
        "value": "ecs_codedeploy_role"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "AWSCodeDeployRole$"
     }
    }
   ],
   "quote": "attached to the AWSCodeDeployRole managed policy"
  },
  {
   "id": "cd_policy_perms",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecs:([a-z]*tasksets?|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)elasticloadbalancing:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)lambda:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cloudwatch:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)sns:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "__declared__"
      ],
      "where": [
       {
        "path": [],
        "op": "contains",
        "value": "\"name\": \"ecs_codedeploy_role_policy\""
       }
      ]
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)s3:"
     }
    }
   ],
   "quote": "inline policies \"ecs_codedeploy_role_policy\" for ECS task set, ELB, Lambda, CloudWatch, SNS, and S3 access",
   "justify": "ELB maps to the elasticloadbalancing IAM prefix"
  },
  {
   "id": "passrole_task",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "to": "task"
    },
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
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "task"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "ecsTaskRole"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": ":role/ecsTaskRole"
     }
    }
   ],
   "quote": "separate PassRole policies (\"ecs_codedeploy_role_policy_task\" and \"ecs_codedeploy_role_policy_task_exec\") targeting the task and execution role ARNs"
  },
  {
   "id": "passrole_exec",
   "tier": "core",
   "kind": "any_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "to": "exec"
    },
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
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "exec"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "ecsExecTaskRole"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ecs_codedeploy_role_policy_task_exec"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": ":role/ecsExecTaskRole"
     }
    }
   ],
   "quote": "separate PassRole policies (\"ecs_codedeploy_role_policy_task\" and \"ecs_codedeploy_role_policy_task_exec\") targeting the task and execution role ARNs"
  },
  {
   "id": "passrole_action",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:passrole"
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
         "name"
        ],
        "op": "regex",
        "value": "^ecs_codedeploy_role_policy_task"
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
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "iam:PassRole"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^ecs_codedeploy_role_policy_task"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:passrole"
     }
    }
   ],
   "quote": "separate PassRole policies"
  },
  {
   "id": "x_svc_register",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role_policy",
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecsTaskRolePolicy"
     }
    ]
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "regex",
    "value": "(?i)elasticloadbalancing:RegisterInstancesWithLoadBalancer"
   }
  },
  {
   "id": "x_svc_sg",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role_policy",
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecsTaskRolePolicy"
     }
    ]
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "regex",
    "value": "(?i)ec2:AuthorizeSecurityGroupIngress"
   }
  },
  {
   "id": "x_exec_ecr",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role_policy",
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecsExecRolePolicy"
     }
    ]
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "regex",
    "value": "(?i)ecr:GetAuthorizationToken"
   }
  },
  {
   "id": "x_cd_taskset",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role_policy",
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecs_codedeploy_role_policy"
     }
    ]
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "regex",
    "value": "(?i)ecs:UpdateServicePrimaryTaskSet"
   }
  },
  {
   "id": "x_cd_lambda",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role_policy",
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ecs_codedeploy_role_policy"
     }
    ]
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "regex",
    "value": "(?i)lambda:InvokeFunction"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
