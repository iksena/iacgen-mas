package intent.cfn.row_259

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "tables": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "api": {
   "types": [
    "AWS::ApiGatewayV2::Api"
   ],
   "where": []
  },
  "routes": {
   "types": [
    "AWS::ApiGatewayV2::Route"
   ],
   "where": []
  },
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "stage": {
   "types": [
    "AWS::ApiGatewayV2::Stage"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "pyfn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": [
    {
     "path": [
      "Runtime"
     ],
     "op": "regex",
     "value": "^python"
    }
   ]
  },
  "lambda_role": {
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
  },
  "default_stage": {
   "types": [
    "AWS::ApiGatewayV2::Stage"
   ],
   "where": [
    {
     "path": [
      "StageName"
     ],
     "op": "in",
     "value": [
      "$default",
      "default"
     ]
    }
   ]
  },
  "lg7": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": [
    {
     "path": [
      "RetentionInDays"
     ],
     "op": "eq",
     "value": 7
    }
   ]
  },
  "integration": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "four_tables",
   "kind": "exists",
   "tier": "core",
   "quote": "four DynamoDB tables",
   "select": "tables",
   "min": 4
  },
  {
   "id": "provisioned",
   "kind": "attr",
   "tier": "detail",
   "quote": "with modest provisioned throughput",
   "select": "tables",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "ReadCapacityUnits"
    ],
    "op": "present"
   },
   "quantifier": "all"
  },
  {
   "id": "provisioned_write",
   "kind": "attr",
   "tier": "detail",
   "quote": "with modest provisioned throughput",
   "select": "tables",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "WriteCapacityUnits"
    ],
    "op": "present"
   },
   "quantifier": "all"
  },
  {
   "id": "config_table",
   "tier": "core",
   "quote": "configuration keyed on a configuration key",
   "justify": "keyed on means HASH key; day as a sort key means RANGE key",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": [
     {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)(config|^key$)"
       }
      ]
     }
    ]
   }
  },
  {
   "id": "services_table",
   "tier": "core",
   "quote": "services keyed on a service identifier",
   "justify": "keyed on means HASH key; day as a sort key means RANGE key",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": [
     {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)(service|svc)"
       }
      ]
     }
    ]
   }
  },
  {
   "id": "oncall_team_key",
   "tier": "core",
   "quote": "on call schedules keyed on a team identifier with the day as a sort key",
   "justify": "keyed on means HASH key; day as a sort key means RANGE key",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": [
     {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)team"
       }
      ]
     },
     {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "RANGE"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)(day|date)"
       }
      ]
     }
    ]
   }
  },
  {
   "id": "incidents_table",
   "kind": "exists",
   "tier": "core",
   "quote": "incidents keyed on an incident identifier",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": [
     {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)incident"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means HASH key; day as a sort key means RANGE key"
  },
  {
   "id": "two_lambdas",
   "kind": "exists",
   "tier": "core",
   "quote": "Two Python Lambda functions",
   "select": "fn",
   "min": 2
  },
  {
   "id": "python",
   "tier": "core",
   "quote": "Two Python Lambda functions",
   "kind": "exists",
   "select": "pyfn",
   "min": 2
  },
  {
   "id": "fn_uses_role",
   "tier": "core",
   "quote": "should share a single execution role",
   "justify": "a Lambda execution role is assumed by the Lambda service; share means every function points at that role",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "pyfn",
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "pyfn",
     "quantifier": "all",
     "cond": {
      "path": [
       "Role",
       "ref"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "lambda_role",
   "tier": "core",
   "quote": "a single execution role",
   "justify": "a single execution role means one role assumed by the Lambda service",
   "kind": "exists",
   "select": "lambda_role",
   "min": 1,
   "max": 1
  },
  {
   "id": "notifier_ses",
   "tier": "detail",
   "quote": "a notifier that sends email through SES",
   "justify": "sending through SES needs a SES send permission on the functions' role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "ses:SendEmail"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "ses:SendRawEmail"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(AmazonSESFullAccess|AdministratorAccess)$"
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
        "value": "ses:SendEmail"
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
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
        "value": "ses:SendRawEmail"
       }
      ]
     },
     "to": "lambda_role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "state_machine",
   "kind": "exists",
   "tier": "core",
   "quote": "a Step Functions state machine",
   "select": "sm"
  },
  {
   "id": "parallel",
   "kind": "attr",
   "tier": "core",
   "quote": "runs two branches in parallel",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)Type\\W+Parallel"
   }
  },
  {
   "id": "wait_300",
   "tier": "core",
   "quote": "the other waiting five minutes before sending an escalation notification",
   "justify": "five minutes is 300 seconds",
   "kind": "attr",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(\\b|wait|delay)Seconds\\W+300\\b"
   }
  },
  {
   "id": "wait_state",
   "kind": "attr",
   "tier": "detail",
   "quote": "waiting five minutes",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)Type\\W+Wait"
   }
  },
  {
   "id": "retries",
   "kind": "attr",
   "tier": "core",
   "quote": "with retries on transient Lambda errors",
   "select": "sm",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?s)(?i)Retry.{0,400}(Lambda\\.|States\\.)"
   }
  },
  {
   "id": "sm_invokes_lambda",
   "kind": "ref",
   "tier": "detail",
   "quote": "one notifying the current on call responder immediately",
   "from": "sm",
   "to": "fn"
  },
  {
   "id": "http_api",
   "kind": "attr",
   "tier": "core",
   "quote": "an HTTP API",
   "select": "api",
   "cond": {
    "path": [
     "ProtocolType"
    ],
    "op": "eq",
    "value": "HTTP"
   }
  },
  {
   "id": "route_get",
   "tier": "core",
   "quote": "routes to retrieve and to create or update an incident by identifier",
   "justify": "retrieve means a GET route with an incident identifier path parameter; ANY also serves GET",
   "kind": "attr",
   "select": "routes",
   "cond": {
    "path": [
     "RouteKey"
    ],
    "op": "regex",
    "value": "^(?i)(GET|ANY)\\s.*\\{"
   }
  },
  {
   "id": "route_write",
   "tier": "core",
   "quote": "routes to retrieve and to create or update an incident by identifier",
   "justify": "create or update means a POST, PUT or PATCH route; ANY also serves those",
   "kind": "attr",
   "select": "routes",
   "cond": {
    "path": [
     "RouteKey"
    ],
    "op": "regex",
    "value": "^(?i)(POST|PUT|PATCH|ANY)\\s"
   }
  },
  {
   "id": "integration_lambda",
   "tier": "core",
   "quote": "an incident processor that handles incoming API requests",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "routes",
     "to": "integration"
    },
    {
     "kind": "ref",
     "from": "integration",
     "to": "fn"
    }
   ]
  },
  {
   "id": "default_stage",
   "tier": "core",
   "quote": "automatically deployed to a default stage",
   "kind": "exists",
   "select": "default_stage"
  },
  {
   "id": "auto_deploy",
   "tier": "core",
   "quote": "automatically deployed to a default stage",
   "kind": "attr",
   "select": "default_stage",
   "cond": {
    "path": [
     "AutoDeploy"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "access_logging",
   "tier": "core",
   "quote": "access logging into a log group",
   "kind": "attr",
   "select": "default_stage",
   "cond": {
    "path": [
     "AccessLogSettings",
     "DestinationArn"
    ],
    "op": "present"
   }
  },
  {
   "id": "log_retention_7",
   "tier": "core",
   "quote": "access logging into a log group that keeps seven days of history",
   "justify": "seven days of history is 7 days retention",
   "kind": "ref",
   "from": "default_stage",
   "to": "lg7"
  },
  {
   "id": "stage_log_group",
   "tier": "detail",
   "quote": "access logging into a log group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "default_stage",
     "to": "lg"
    },
    {
     "kind": "attr",
     "select": "default_stage",
     "cond": {
      "path": [
       "AccessLogSettings",
       "DestinationArn"
      ],
      "op": "regex",
      "value": "(?i)arn:[^:]*:logs:"
     }
    }
   ],
   "justify": "a CloudWatch log group destination is an ARN in the logs service"
  },
  {
   "id": "sender_param",
   "tier": "core",
   "quote": "The sender email address should be a parameter",
   "justify": "a parameter holding an email address either says so in its name or has an address as its default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(sender|e-?mail|from.?addr)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "@"
     }
    }
   ]
  },
  {
   "id": "three_ssm",
   "kind": "exists",
   "tier": "core",
   "quote": "each be published to SSM Parameter Store",
   "select": "ssm",
   "min": 3
  },
  {
   "id": "ssm_paths",
   "kind": "attr",
   "tier": "detail",
   "quote": "under an application specific path",
   "select": {
    "types": [
     "AWS::SSM::Parameter"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^/[^/]+/"
   },
   "quantifier": "all"
  },
  {
   "id": "ssm_sender",
   "kind": "any_of",
   "tier": "core",
   "quote": "The sender email address should be a parameter, and that address, the state machine identifier and the API endpoint should each be published to SSM Parameter Store",
   "justify": "the sender email value contains an @ or the parameter name says it is the email",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "@"
     }
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)(email|sender|from)"
     }
    }
   ]
  },
  {
   "id": "ssm_state_machine",
   "kind": "ref",
   "tier": "core",
   "quote": "the state machine identifier",
   "from": "ssm",
   "to": "sm"
  },
  {
   "id": "ssm_api_endpoint",
   "kind": "any_of",
   "tier": "core",
   "quote": "the API endpoint",
   "checks": [
    {
     "kind": "ref",
     "from": "ssm",
     "to": "api"
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "(?i)execute-api"
     }
    }
   ]
  },
  {
   "id": "x_integration_proxy",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGatewayV2::Integration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "IntegrationType"
    ],
    "op": "eq",
    "value": "AWS_PROXY"
   }
  },
  {
   "id": "x_payload_v2",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGatewayV2::Integration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PayloadFormatVersion"
    ],
    "op": "eq",
    "value": "2.0"
   }
  },
  {
   "id": "x_role_ddb",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "regex",
      "value": "^(?i)(dynamodb:(\\*|GetItem|PutItem|Query)|\\*)$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "regex",
      "value": "^(?i)(dynamodb:(\\*|GetItem|PutItem|Query)|\\*)$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
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
      "value": "^(?i)(dynamodb:(\\*|GetItem|PutItem|Query)|\\*)$"
     }
    }
   ]
  },
  {
   "id": "extra_type_aws_lambda_permission",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Lambda::Permission"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
