package intent.tf.row_097

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "name_var",
   "tier": "detail",
   "quote": "an optional name variable defaulting to null",
   "kind": "attr",
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
      "value": "name"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": null
   }
  },
  {
   "id": "name_fallback_default",
   "tier": "detail",
   "quote": "fall back to \"default\" if null or empty",
   "kind": "attr",
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
    "value": "default-invoke"
   },
   "justify": "name defaults to null, so the module name falls back to \"default\" and the role is named default plus \"-invoke\""
  },
  {
   "id": "collection_inputs_empty",
   "tier": "detail",
   "quote": "a tags map defaulting to empty, a bus configuration map defaulting to empty (which validates non-null input and supports an optional event_source_name parameter defaulting to null), a rules list defaulting to empty (which validates non-null input), and a targets list defaulting to empty",
   "kind": "all_of",
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
        "op": "len_eq",
        "value": 0
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
        "value": "(?i)bus"
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
        "value": "(?i)rules"
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
        "value": "(?i)targets"
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
   "id": "bus_conditional",
   "tier": "core",
   "quote": "A custom EventBridge bus named after the module name must be conditionally created",
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
      "value": "aws_cloudwatch_event_bus"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "bus_event_source",
   "tier": "detail",
   "quote": "supports an optional event_source_name parameter defaulting to null",
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
      "value": "aws_cloudwatch_event_bus"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "event_source_name"
    ],
    "op": "present"
   }
  },
  {
   "id": "rules_generated",
   "tier": "core",
   "quote": "EventBridge rules defined in the rules list must be generated using each rule's name key",
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
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "each\\."
     }
    ]
   }
  },
  {
   "id": "rule_params",
   "tier": "detail",
   "quote": "inheriting optional parameters for description, event_pattern, and schedule_expression (defaulting to null)",
   "kind": "all_of",
   "checks": [
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
        "value": "aws_cloudwatch_event_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "description"
      ],
      "op": "present"
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
        "value": "aws_cloudwatch_event_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "event_pattern"
      ],
      "op": "present"
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
        "value": "aws_cloudwatch_event_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "schedule_expression"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "rule_on_bus",
   "tier": "detail",
   "quote": "while attaching to the custom event bus if created",
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
      "value": "aws_cloudwatch_event_rule"
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
      "value": "aws_cloudwatch_event_bus"
     }
    ]
   }
  },
  {
   "id": "role_invoke",
   "tier": "core",
   "quote": "an IAM role named after the module name with an \"-invoke\" suffix",
   "kind": "any_of",
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
       "name"
      ],
      "op": "regex",
      "value": "-invoke$"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "invoke"
     }
    }
   ]
  },
  {
   "id": "role_events_principal",
   "tier": "core",
   "quote": "assumed by the EventBridge service principal (\"events.<dns_suffix>\")",
   "kind": "any_of",
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
      "value": "events\\."
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "events\\."
     }
    },
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
        "op": "regex",
        "value": "^events\\."
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_name",
   "tier": "detail",
   "quote": "an inline policy named after the module name with an \"-invoke-targets\" suffix",
   "kind": "any_of",
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
       "inline_policy",
       "*",
       "name"
      ],
      "op": "regex",
      "value": "-invoke-targets$"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "inline_policy"
      ],
      "op": "regex",
      "value": "invoke-targets"
     }
    },
    {
     "kind": "exists",
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
        "value": "-invoke-targets$"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "invoke-targets"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_lambda",
   "tier": "core",
   "quote": "permitting \"lambda:InvokeFunction\"",
   "kind": "any_of",
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
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(InvokeFunction|\\*)"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(InvokeFunction|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(InvokeFunction|\\*)"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(InvokeFunction|\\*)"
     }
    }
   ]
  },
  {
   "id": "policy_states",
   "tier": "core",
   "quote": "\"states:StartExecution\"",
   "kind": "any_of",
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
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)states:(StartExecution|\\*)"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)states:(StartExecution|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)states:(StartExecution|\\*)"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)states:(StartExecution|\\*)"
     }
    }
   ]
  },
  {
   "id": "policy_all_resources",
   "tier": "detail",
   "quote": "across all resources",
   "kind": "any_of",
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
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "Resource[^*A-Za-z]{1,8}\\*"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "inline_policy"
      ],
      "op": "regex",
      "value": "Resource[^*A-Za-z]{1,8}\\*"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "Resource[^*A-Za-z]{1,8}\\*"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "Resource[^*A-Za-z]{1,8}\\*"
     }
    }
   ]
  },
  {
   "id": "targets_generated",
   "tier": "core",
   "quote": "event targets defined in the targets list must be generated",
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
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "targets_depend_on_rules",
   "tier": "detail",
   "quote": "with explicit dependencies on the rules, linking each target's specified rule and ARN",
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
      "value": "aws_cloudwatch_event_target"
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
      "value": "aws_cloudwatch_event_rule"
     }
    ]
   }
  },
  {
   "id": "targets_on_bus",
   "tier": "detail",
   "quote": "attaching to the custom event bus if created",
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
      "value": "aws_cloudwatch_event_target"
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
      "value": "aws_cloudwatch_event_bus"
     }
    ]
   }
  },
  {
   "id": "target_role_for_statemachine",
   "tier": "detail",
   "quote": "dynamically assigning the created IAM role ARN only if the target ARN contains \"stateMachine\"",
   "kind": "all_of",
   "checks": [
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
        "value": "aws_cloudwatch_event_target"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "role_arn"
      ],
      "op": "regex",
      "value": "stateMachine"
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
        "value": "aws_cloudwatch_event_target"
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
        "value": "aws_iam_role"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
