package intent.cfn.row_230

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "conn": {
   "types": [
    "AWS::Events::Connection"
   ],
   "where": []
  },
  "dest": {
   "types": [
    "AWS::Events::ApiDestination"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "ev_role": {
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
     "value": "events.amazonaws.com"
    }
   ]
  },
  "iam_pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "xrole": {
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
      "AWS"
     ],
     "op": "present"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "AWS",
      "*"
     ],
     "op": "none_eq",
     "value": "*"
    }
   ]
  },
  "flags": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "allowed_values"
     ],
     "op": "regex",
     "value": "(?i)true|enabled|yes"
    }
   ]
  },
  "req_params": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)endpoint"
    }
   ]
  },
  "boundary": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::IAM::ManagedPolicy"
    }
   ]
  },
  "custom": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "regex",
     "value": "^(Custom::|AWS::CloudFormation::CustomResource)"
    }
   ]
  },
  "flags_by_default": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "in",
     "value": [
      "true",
      "false",
      "yes",
      "no",
      "enabled",
      "disabled"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "endpoint_param",
   "kind": "exists",
   "select": "req_params",
   "tier": "core",
   "quote": "Given our marbot endpoint ID as a parameter"
  },
  {
   "id": "event_connection",
   "kind": "exists",
   "select": "conn",
   "tier": "core",
   "quote": "an EventBridge API destination and connection"
  },
  {
   "id": "api_key_auth",
   "kind": "attr",
   "select": "conn",
   "cond": {
    "path": [
     "AuthorizationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   },
   "tier": "core",
   "quote": "authenticated with an API key derived from that endpoint ID"
  },
  {
   "id": "api_key_value",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an API key derived from that endpoint ID",
   "checks": [
    {
     "kind": "attr",
     "select": "conn",
     "cond": {
      "path": [
       "AuthParameters",
       "ApiKeyAuthParameters",
       "ApiKeyValue"
      ],
      "op": "regex",
      "value": "(?i)endpoint"
     }
    },
    {
     "kind": "join",
     "from": "conn",
     "from_path": [
      "AuthParameters",
      "ApiKeyAuthParameters",
      "ApiKeyValue"
     ],
     "to": "req_params",
     "to_path": [
      "default"
     ]
    }
   ]
  },
  {
   "id": "api_destination",
   "kind": "exists",
   "select": "dest",
   "tier": "core",
   "quote": "an EventBridge API destination and connection"
  },
  {
   "id": "destination_uses_connection",
   "kind": "ref",
   "from": "dest",
   "to": "conn",
   "tier": "core",
   "quote": "an EventBridge API destination and connection"
  },
  {
   "id": "destination_post",
   "kind": "attr",
   "select": "dest",
   "cond": {
    "path": [
     "HttpMethod"
    ],
    "op": "eq",
    "value": "POST"
   },
   "tier": "detail",
   "quote": "post our account and stack identification details"
  },
  {
   "id": "destination_marbot",
   "kind": "attr",
   "select": "dest",
   "cond": {
    "path": [
     "InvocationEndpoint"
    ],
    "op": "regex",
    "value": "(?i)marbot"
   },
   "tier": "detail",
   "quote": "to marbot's service"
  },
  {
   "id": "schedule_rule",
   "kind": "any_of",
   "tier": "core",
   "quote": "a scheduled rule that runs every 30 days",
   "justify": "30 days is rate(30 days), 720 hours or 43200 minutes",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)rate\\(\\s*30\\s+days\\s*\\)"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)rate\\(\\s*(720\\s+hours|43200\\s+minutes)\\s*\\)"
     }
    }
   ]
  },
  {
   "id": "rule_targets_destination",
   "kind": "ref",
   "from": "rule",
   "to": "dest",
   "tier": "core",
   "quote": "a scheduled rule that runs every 30 days to post our account and stack identification details to marbot's service"
  },
  {
   "id": "rule_uses_invoke_role",
   "kind": "ref",
   "from": "rule",
   "to": "ev_role",
   "tier": "detail",
   "quote": "the IAM role EventBridge needs to invoke that destination"
  },
  {
   "id": "rule_posts_account",
   "kind": "any_of",
   "tier": "detail",
   "quote": "post our account and stack identification details",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Input"
      ],
      "op": "regex",
      "value": "(?i)account"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "InputTransformer"
      ],
      "op": "regex",
      "value": "(?i)account"
     }
    }
   ]
  },
  {
   "id": "rule_posts_stack",
   "kind": "any_of",
   "tier": "detail",
   "quote": "post our account and stack identification details",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Input"
      ],
      "op": "regex",
      "value": "(?i)stack"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "InputTransformer"
      ],
      "op": "regex",
      "value": "(?i)stack"
     }
    }
   ]
  },
  {
   "id": "invoke_role",
   "kind": "exists",
   "select": "ev_role",
   "tier": "core",
   "quote": "the IAM role EventBridge needs to invoke that destination",
   "justify": "EventBridge principal is events.amazonaws.com"
  },
  {
   "id": "invoke_role_permission",
   "kind": "any_of",
   "tier": "core",
   "quote": "the IAM role EventBridge needs to invoke that destination",
   "justify": "invoking an API destination is events:InvokeApiDestination",
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
      "value": "events:InvokeApiDestination"
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
        "value": "events:InvokeApiDestination"
       }
      ]
     },
     "to": "ev_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "cross_account_role",
   "kind": "exists",
   "select": "xrole",
   "tier": "core",
   "quote": "a cross-account IAM role that marbot's AWS account can assume",
   "justify": "assumable by an AWS account principal"
  },
  {
   "id": "external_id",
   "kind": "attr",
   "select": "xrole",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Condition",
     "*",
     "sts:ExternalId"
    ],
    "op": "regex",
    "value": "(?i)^id$|stack"
   },
   "tier": "core",
   "quote": "using an external ID unique to this stack",
   "justify": "unique to this stack means built from the stack ID or name, which the adapter renders as id, stack or a stack ARN"
  },
  {
   "id": "feature_flags",
   "kind": "any_of",
   "tier": "core",
   "quote": "separate boolean feature flags",
   "justify": "four listed features (monitoring, account aliases, metric graphs, CodePipeline approval) each get a flag; a flag may say true/false or Enabled/Disabled",
   "checks": [
    {
     "kind": "exists",
     "select": "flags",
     "min": 4
    },
    {
     "kind": "exists",
     "select": "flags_by_default",
     "min": 4
    }
   ]
  },
  {
   "id": "flag_per_feature",
   "kind": "all_of",
   "tier": "detail",
   "quote": "separate boolean feature flags",
   "justify": "a flag name for each of the four listed features",
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
        "value": "(?i)monitor|alarm|assistant"
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
        "value": "(?i)alias"
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
        "value": "(?i)graph|widget|metric"
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
        "value": "(?i)approv|pipeline"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "permissions_boundary_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "restricted by an IAM permissions boundary policy created by the stack",
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
        "value": "AWS::IAM::Role"
       },
       {
        "path": [
         "properties",
         "PermissionsBoundary"
        ],
        "op": "present"
       }
      ]
     },
     "to": "boundary"
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
        "value": "AWS::IAM::ManagedPolicy"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i)monitor|assistant"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "custom_resource",
   "kind": "exists",
   "select": "custom",
   "tier": "core",
   "quote": "register the account connection with marbot's service using a custom resource"
  },
  {
   "id": "x_custom_resource_role",
   "kind": "ref",
   "from": "custom",
   "to": "xrole",
   "tier": "extra"
  },
  {
   "id": "x_rule_enabled",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "State"
    ],
    "op": "eq",
    "value": "ENABLED"
   },
   "tier": "extra"
  },
  {
   "id": "x_dest_rate_limit",
   "kind": "attr",
   "select": "dest",
   "cond": {
    "path": [
     "InvocationRateLimitPerSecond"
    ],
    "op": "present"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
