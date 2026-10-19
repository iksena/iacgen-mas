package intent.tf.row_161

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cd_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "codedeploy.amazonaws.com"
    }
   ]
  },
  "dg": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_codedeploy_deployment_group"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "codedeploy_role",
   "kind": "exists",
   "tier": "core",
   "quote": "create an IAM role with assume policy for specified CodeDeploy service principals (defaulting to \"codedeploy.amazonaws.com\")",
   "select": "cd_role"
  },
  {
   "id": "lambda_managed_policy",
   "kind": "ref",
   "tier": "core",
   "quote": "attach the \"AWSCodeDeployRoleForLambda\" managed policy",
   "to": "cd_role",
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
      "op": "regex",
      "value": "policy/(service-role/)?AWSCodeDeployRoleForLambda$"
     }
    ]
   }
  },
  {
   "id": "principals_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "specified CodeDeploy service principals (defaulting to \"codedeploy.amazonaws.com\")",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "contains",
      "value": "codedeploy.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "lambda_codedeploy_app",
   "kind": "exists",
   "tier": "core",
   "quote": "create a Lambda compute platform CodeDeploy application",
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
      "value": "aws_codedeploy_app"
     },
     {
      "path": [
       "properties",
       "compute_platform"
      ],
      "op": "contains",
      "value": "Lambda"
     }
    ]
   }
  },
  {
   "id": "deployment_group_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "provision a deployment group",
   "select": "dg"
  },
  {
   "id": "dg_config_name",
   "kind": "attr",
   "tier": "core",
   "quote": "bound to deployment_config_name (defaulting to \"CodeDeployDefault.LambdaAllAtOnce\")",
   "select": "dg",
   "cond": {
    "path": [
     "properties",
     "deployment_config_name"
    ],
    "op": "contains",
    "value": "CodeDeployDefault.LambdaAllAtOnce"
   }
  },
  {
   "id": "dg_blue_green_traffic",
   "kind": "all_of",
   "tier": "core",
   "quote": "configured with \"WITH_TRAFFIC_CONTROL\" and \"BLUE_GREEN\" deployment styles",
   "checks": [
    {
     "kind": "attr",
     "select": "dg",
     "cond": {
      "path": [
       "properties",
       "deployment_style"
      ],
      "op": "contains",
      "value": "WITH_TRAFFIC_CONTROL"
     }
    },
    {
     "kind": "attr",
     "select": "dg",
     "cond": {
      "path": [
       "properties",
       "deployment_style"
      ],
      "op": "contains",
      "value": "BLUE_GREEN"
     }
    }
   ]
  },
  {
   "id": "dg_auto_rollback",
   "kind": "attr",
   "tier": "core",
   "quote": "automatic rollbacks enabled by default on \"DEPLOYMENT_STOP_ON_ALARM\"",
   "select": "dg",
   "cond": {
    "path": [
     "properties",
     "auto_rollback_configuration"
    ],
    "op": "contains",
    "value": "DEPLOYMENT_STOP_ON_ALARM"
   }
  },
  {
   "id": "dg_alarms_and_triggers",
   "kind": "all_of",
   "tier": "detail",
   "quote": "optional CloudWatch alarm monitoring, and notification triggers",
   "checks": [
    {
     "kind": "attr",
     "select": "dg",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "alarm_configuration"
     }
    },
    {
     "kind": "attr",
     "select": "dg",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "trigger_configuration"
     }
    }
   ]
  },
  {
   "id": "hooks_policy_invoke",
   "kind": "exists",
   "tier": "detail",
   "quote": "conditionally attach inline policies granting lambda:InvokeFunction for specified hooks",
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
       "data.aws_iam_policy_document",
       "aws_iam_role"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "lambda:InvokeFunction"
     }
    ]
   }
  },
  {
   "id": "triggers_policy_publish",
   "kind": "exists",
   "tier": "detail",
   "quote": "sns:Publish for triggers when attach_triggers_policy is true",
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
       "data.aws_iam_policy_document",
       "aws_iam_role"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "sns:Publish"
     }
    ]
   }
  },
  {
   "id": "deploy_script_file",
   "kind": "exists",
   "tier": "detail",
   "quote": "optionally saving the generated script locally",
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
      "value": "local_file"
     }
    ]
   }
  },
  {
   "id": "deploy_provisioner",
   "kind": "exists",
   "tier": "detail",
   "quote": "executing the deployment provisioner via a null resource",
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
      "value": "null_resource"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "local-exec"
     }
    ]
   }
  },
  {
   "id": "force_deploy_uuid",
   "kind": "attr",
   "tier": "detail",
   "quote": "optional uuid-based force_deploy triggers",
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
      "value": "null_resource"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "triggers"
    ],
    "op": "regex",
    "value": "(?i)uuid"
   },
   "justify": "uuid-based trigger: uuid() function or a random_uuid resource"
  },
  {
   "id": "vars_global",
   "kind": "all_of",
   "tier": "core",
   "quote": "a boolean create variable defaulting to true, accepting a function_name, alias_name, current_version, and target_version alongside optional before_allow_traffic_hook_arn and after_allow_traffic_hook_arn",
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
        "op": "eq",
        "value": "create"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": true
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
        "op": "eq",
        "value": "function_name"
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
        "op": "eq",
        "value": "alias_name"
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
        "op": "eq",
        "value": "current_version"
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
        "op": "eq",
        "value": "target_version"
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
        "op": "eq",
        "value": "before_allow_traffic_hook_arn"
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
        "op": "eq",
        "value": "after_allow_traffic_hook_arn"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vars_app",
   "kind": "all_of",
   "tier": "detail",
   "quote": "When create_app is true and use_existing_app is false (both defaulting to false)",
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
        "op": "eq",
        "value": "create_app"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "use_existing_app"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "app_name"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vars_deployment_group",
   "kind": "all_of",
   "tier": "detail",
   "quote": "when create_deployment_group is true and use_existing_deployment_group is false (both defaulting to false)",
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
        "op": "eq",
        "value": "create_deployment_group"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "use_existing_deployment_group"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "deployment_config_name"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "CodeDeployDefault.LambdaAllAtOnce"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vars_role",
   "kind": "all_of",
   "tier": "detail",
   "quote": "When create_codedeploy_role is true (defaulting to true)",
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
        "op": "eq",
        "value": "create_codedeploy_role"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": true
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
        "op": "eq",
        "value": "attach_hooks_policy"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": true
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
        "op": "eq",
        "value": "attach_triggers_policy"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vars_deployment",
   "kind": "all_of",
   "tier": "detail",
   "quote": "when create_deployment is true (defaulting to false)",
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
        "op": "eq",
        "value": "create_deployment"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "aws_cli_command"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "aws"
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
        "op": "eq",
        "value": "get_deployment_sleep_timer"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 5
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
        "op": "eq",
        "value": "save_deploy_script"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "op": "eq",
        "value": "run_deployment"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
       }
      ]
     }
    }
   ]
  },
  {
   "id": "app_gate",
   "kind": "attr",
   "tier": "detail",
   "quote": "When create_app is true and use_existing_app is false",
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
      "value": "aws_codedeploy_app"
     }
    ]
   },
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "create_app|local\\."
   },
   "justify": "gate must reference create_app (directly or through a local, which is unresolved)"
  },
  {
   "id": "dg_gate",
   "kind": "attr",
   "tier": "detail",
   "quote": "when create_deployment_group is true and use_existing_deployment_group is false",
   "select": "dg",
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "create_deployment_group|local\\."
   },
   "justify": "gate must reference create_deployment_group (directly or through a local, which is unresolved)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
