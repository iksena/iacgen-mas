package intent.cfn.row_090

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "gw_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "bedrock-agentcore.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "none_eq",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "gw_loose": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)bedrock"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "none_eq",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "fn_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "lambda.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "function_named",
   "kind": "attr",
   "tier": "core",
   "quote": "a Lambda function named bac-mcp-tool",
   "select": "fn",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "eq",
    "value": "bac-mcp-tool"
   }
  },
  {
   "id": "python312",
   "kind": "attr",
   "tier": "core",
   "quote": "The function should run on Python 3.12",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.12"
   }
  },
  {
   "id": "generous_timeout",
   "kind": "attr",
   "tier": "detail",
   "quote": "a generous timeout",
   "select": "fn",
   "cond": {
    "path": [
     "Timeout"
    ],
    "op": "gte",
    "value": 60
   },
   "justify": "generous means well above the 3 second default"
  },
  {
   "id": "generous_memory",
   "kind": "attr",
   "tier": "detail",
   "quote": "memory allocation suitable for long-running operations work",
   "select": "fn",
   "cond": {
    "path": [
     "MemorySize"
    ],
    "op": "gte",
    "value": 512
   },
   "justify": "well above the 128 MB default"
  },
  {
   "id": "xray_active",
   "kind": "attr",
   "tier": "core",
   "quote": "active X-Ray tracing enabled",
   "select": "fn",
   "cond": {
    "path": [
     "TracingConfig",
     "Mode"
    ],
    "op": "eq",
    "value": "Active"
   }
  },
  {
   "id": "fn_bedrock_invoke",
   "kind": "any_of",
   "tier": "core",
   "quote": "invoke Bedrock foundation models",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "bedrock:InvokeModel"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "bedrock:InvokeModel"
       }
      ]
     },
     "to": "fn_role"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "bedrock:InvokeModel"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AmazonBedrock"
     }
    }
   ]
  },
  {
   "id": "fn_cost_explorer",
   "kind": "any_of",
   "tier": "core",
   "quote": "query AWS Cost Explorer and cost and usage data",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "ce:GetCostAndUsage"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "ce:GetCostAndUsage"
       }
      ]
     },
     "to": "fn_role"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "ce:GetCostAndUsage"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(billing|costexplorer|policy/ReadOnlyAccess$)"
     }
    }
   ]
  },
  {
   "id": "fn_s3_objects",
   "kind": "any_of",
   "tier": "core",
   "quote": "perform basic S3 object operations",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "s3:GetObject"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "fn_role"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(AmazonS3|policy/ReadOnlyAccess$)"
     }
    }
   ]
  },
  {
   "id": "fn_logs",
   "kind": "any_of",
   "tier": "core",
   "quote": "write its own CloudWatch Logs",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "logs:PutLogEvents"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "fn_role"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(AWSLambdaBasicExecutionRole|CloudWatchLogs)"
     }
    }
   ]
  },
  {
   "id": "gateway_role",
   "kind": "exists",
   "tier": "core",
   "quote": "a dedicated IAM execution role that the Bedrock AgentCore Gateway service itself can assume",
   "select": "gw_role",
   "justify": "dedicated means the role is not also the function's Lambda role"
  },
  {
   "id": "gateway_role_scoped",
   "kind": "attr",
   "tier": "core",
   "quote": "scoped so it can only be assumed for gateways belonging to the same AWS account",
   "select": "gw_loose",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Condition"
    ],
    "op": "regex",
    "value": "(?i)(aws:sourceaccount|aws:sourcearn)"
   }
  },
  {
   "id": "gw_invoke_lambda",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permissions to invoke Lambda functions",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_loose",
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
      "value": "lambda:InvokeFunction"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "lambda:InvokeFunction"
       }
      ]
     },
     "to": "gw_loose"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "lambda:InvokeFunction"
       }
      ]
     },
     "to": "gw_loose",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "gw_agentcore",
   "kind": "any_of",
   "tier": "detail",
   "quote": "manage Bedrock AgentCore resources",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_loose",
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
      "op": "regex",
      "value": "(?i)^(bedrock-agentcore:.+|\\*)$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "op": "regex",
        "value": "(?i)^(bedrock-agentcore:.+|\\*)$"
       }
      ]
     },
     "to": "gw_loose"
    },
    {
     "kind": "ref",
     "from": {
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
        "op": "regex",
        "value": "(?i)^(bedrock-agentcore:.+|\\*)$"
       }
      ]
     },
     "to": "gw_loose",
     "bidirectional": true
    }
   ],
   "justify": "any bedrock-agentcore action counts: the prompt names the resources, not an action"
  },
  {
   "id": "gw_passrole",
   "kind": "any_of",
   "tier": "detail",
   "quote": "pass IAM roles",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_loose",
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
      "value": "iam:PassRole"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "gw_loose"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "iam:PassRole"
       }
      ]
     },
     "to": "gw_loose",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "gw_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "access S3 objects",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_loose",
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
      "value": "s3:GetObject"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "gw_loose"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "gw_loose",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "gw_loose",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AmazonS3"
     }
    }
   ]
  },
  {
   "id": "gw_logs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "write CloudWatch Logs",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_loose",
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
      "value": "logs:PutLogEvents"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "gw_loose"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "gw_loose",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "gw_loose",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)CloudWatchLogs"
     }
    }
   ]
  },
  {
   "id": "log_group",
   "kind": "exists",
   "tier": "core",
   "quote": "A CloudWatch log group should also be created for the function",
   "select": "lg"
  },
  {
   "id": "log_group_two_weeks",
   "kind": "attr",
   "tier": "core",
   "quote": "a two-week retention period",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 14
   },
   "justify": "two weeks is 14 days"
  },
  {
   "id": "log_group_for_function",
   "kind": "any_of",
   "tier": "detail",
   "quote": "A CloudWatch log group should also be created for the function",
   "checks": [
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "LogGroupName"
      ],
      "op": "eq",
      "value": "/aws/lambda/bac-mcp-tool"
     }
    },
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "LogGroupName"
      ],
      "op": "regex",
      "value": "^/aws/lambda/\\$\\{.+\\}$"
     }
    }
   ],
   "justify": "Lambda writes to /aws/lambda/<function name>"
  },
  {
   "id": "x_function_role_trust_lambda",
   "kind": "exists",
   "tier": "extra",
   "select": "fn_role"
  },
  {
   "id": "x_function_has_role",
   "kind": "ref",
   "tier": "extra",
   "from": "fn",
   "to": "fn_role"
  },
  {
   "id": "x_gateway_role_source_arn",
   "kind": "attr",
   "tier": "extra",
   "select": "gw_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "(?i)aws:sourcearn"
   }
  },
  {
   "id": "x_function_cost_explorer_forecast",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "fn_role",
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
      "value": "ce:GetCostForecast"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
        "value": "ce:GetCostForecast"
       }
      ]
     },
     "to": "fn_role"
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "ce:GetCostForecast"
       }
      ]
     },
     "to": "fn_role",
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "fn_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(billing|costexplorer|policy/ReadOnlyAccess$)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
