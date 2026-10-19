package intent.cfn.row_085

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "lambda": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "sm_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "states.amazonaws.com"
    }
   ]
  },
  "ev_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "events.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "hourly_schedule_rule",
   "kind": "attr",
   "select": "rule",
   "tier": "core",
   "quote": "run every hour via an EventBridge rule",
   "cond": {
    "path": [
     "ScheduleExpression"
    ],
    "op": "regex",
    "value": "(?i)^(rate\\(\\s*1\\s+hours?\\s*\\)|rate\\(\\s*60\\s+minutes\\s*\\)|cron\\(\\s*\\d+\\s+\\*\\s+\\*\\s+\\*\\s+\\S+\\s+\\*\\s*\\))$"
   },
   "justify": "every hour = rate(1 hour), rate(60 minutes) or an hourly cron"
  },
  {
   "id": "rule_targets_state_machine",
   "kind": "ref",
   "from": "rule",
   "to": "sm",
   "tier": "core",
   "quote": "invoking an EXPRESS Step Functions state machine"
  },
  {
   "id": "state_machine_express",
   "kind": "attr",
   "select": "sm",
   "tier": "core",
   "quote": "an EXPRESS Step Functions state machine",
   "cond": {
    "path": [
     "StateMachineType"
    ],
    "op": "eq",
    "value": "EXPRESS"
   }
  },
  {
   "id": "finds_accounts_tagged_requested",
   "kind": "any_of",
   "tier": "core",
   "quote": "accounts that are tagged with the key \"organizations:account-closure\" and value \"REQUESTED\"",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?is)account-closure.{0,400}?REQUESTED|REQUESTED.{0,400}?account-closure"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?is)account-closure.{0,400}?REQUESTED|REQUESTED.{0,400}?account-closure"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)account-closure.{0,400}?REQUESTED|REQUESTED.{0,400}?account-closure"
     }
    }
   ]
  },
  {
   "id": "paginates",
   "kind": "any_of",
   "tier": "detail",
   "quote": "paginates through accounts tagged for closure",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)(pagination_?token|next_?token)"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)(pagination_?token|next_?token)"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)(pagination_?token|next_?token|paginat)"
     }
    }
   ],
   "justify": "paginating an AWS list API means passing its pagination/next token"
  },
  {
   "id": "describes_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "describes each account",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)describe_?account"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)describe_?account"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)describe_?account"
     }
    }
   ]
  },
  {
   "id": "checks_active_status",
   "kind": "any_of",
   "tier": "detail",
   "quote": "if it is ACTIVE",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "contains",
      "value": "ACTIVE"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "contains",
      "value": "ACTIVE"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "contains",
      "value": "ACTIVE"
     }
    }
   ]
  },
  {
   "id": "closes_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "closes it using the Organizations CloseAccount API",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)close_?account"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)close_?account"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)close_?account"
     }
    }
   ]
  },
  {
   "id": "tags_acknowledged",
   "kind": "any_of",
   "tier": "core",
   "quote": "then tags the account with \"ACKNOWLEDGED\"",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?is)tag_?resource.{0,600}?ACKNOWLEDGED|ACKNOWLEDGED.{0,600}?tag_?resource"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?is)tag_?resource.{0,600}?ACKNOWLEDGED|ACKNOWLEDGED.{0,600}?tag_?resource"
     }
    },
    {
     "kind": "attr",
     "select": "lambda",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)tag_?resource.{0,600}?ACKNOWLEDGED|ACKNOWLEDGED.{0,600}?tag_?resource"
     }
    }
   ]
  },
  {
   "id": "throttling_retry",
   "kind": "any_of",
   "tier": "detail",
   "quote": "error handling for throttling",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?is)Retry.{0,400}?(TooManyRequests|Throttl|States\\.ALL|States\\.TaskFailed)"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?is)Retry.{0,400}?(TooManyRequests|Throttl|States\\.ALL|States\\.TaskFailed)"
     }
    }
   ]
  },
  {
   "id": "eventual_consistency_handling",
   "kind": "any_of",
   "tier": "detail",
   "quote": "error handling for throttling and eventual consistency",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)(AccountNotFound|Catch|\"?Type\"?\\s*[:=]\\s*\"?Wait)"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)(AccountNotFound|Catch|\"?Type\"?\\s*[:=]\\s*\"?Wait)"
     }
    }
   ]
  },
  {
   "id": "logs_execution_data",
   "kind": "attr",
   "select": "sm",
   "tier": "core",
   "quote": "log all execution data to a CloudWatch log group",
   "cond": {
    "path": [
     "LoggingConfiguration",
     "IncludeExecutionData"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "log_level_all",
   "kind": "attr",
   "select": "sm",
   "tier": "detail",
   "quote": "log all execution data",
   "cond": {
    "path": [
     "LoggingConfiguration",
     "Level"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "justify": "log all execution data = logging Level ALL"
  },
  {
   "id": "logs_to_log_group",
   "kind": "ref",
   "from": "sm",
   "to": "lg",
   "tier": "detail",
   "quote": "log all execution data to a CloudWatch log group"
  },
  {
   "id": "log_group_retention_365",
   "kind": "attr",
   "select": "lg",
   "tier": "core",
   "quote": "a CloudWatch log group with a 365-day retention",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 365
   }
  },
  {
   "id": "sm_role_close_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "IAM roles with least-privilege permissions scoped to the required Organizations and tagging actions",
   "checks": [
    {
     "kind": "attr",
     "select": "sm_role",
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
      "value": "organizations:CloseAccount"
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
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "organizations:CloseAccount"
       }
      ]
     },
     "to": "sm_role"
    },
    {
     "kind": "ref",
     "from": "sm_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy"
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
        "value": "organizations:CloseAccount"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sm_role_tag_resource",
   "kind": "any_of",
   "tier": "detail",
   "quote": "scoped to the required Organizations and tagging actions",
   "checks": [
    {
     "kind": "attr",
     "select": "sm_role",
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
      "value": "organizations:TagResource"
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
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "organizations:TagResource"
       }
      ]
     },
     "to": "sm_role"
    },
    {
     "kind": "ref",
     "from": "sm_role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy"
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
        "value": "organizations:TagResource"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "state_machine_uses_role",
   "kind": "ref",
   "from": "sm",
   "to": "sm_role",
   "tier": "detail",
   "quote": "use IAM roles"
  },
  {
   "id": "least_privilege_no_wildcard_actions",
   "kind": "attr",
   "select": "sm_role",
   "tier": "detail",
   "quote": "least-privilege permissions",
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
  },
  {
   "id": "rule_invoke_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "use IAM roles",
   "checks": [
    {
     "kind": "attr",
     "select": "ev_role",
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
      "value": "states:StartExecution"
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
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "states:StartExecution"
       }
      ]
     },
     "to": "ev_role"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
