package intent.tf.row_286

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "aws_apigatewayv2_api"
   ],
   "where": [
    {
     "path": [
      "protocol_type"
     ],
     "op": "eq",
     "value": "WEBSOCKET"
    }
   ]
  },
  "queue": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "mock_int": {
   "types": [
    "aws_apigatewayv2_integration"
   ],
   "where": [
    {
     "path": [
      "integration_type"
     ],
     "op": "eq",
     "value": "MOCK"
    }
   ]
  },
  "sqs_int": {
   "types": [
    "aws_apigatewayv2_integration"
   ],
   "where": [
    {
     "path": [
      "integration_type"
     ],
     "op": "in",
     "value": [
      "AWS",
      "AWS_PROXY"
     ]
    },
    {
     "path": [],
     "op": "regex",
     "value": "(?i)SendMessage|MessageBody|:sqs:"
    }
   ]
  },
  "stage": {
   "types": [
    "aws_apigatewayv2_stage"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "dev"
    }
   ]
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "websocket_api",
   "kind": "exists",
   "tier": "core",
   "quote": "a WebSocket API on Amazon API Gateway v2",
   "select": "api"
  },
  {
   "id": "sqs_queue",
   "kind": "exists",
   "tier": "core",
   "quote": "an Amazon SQS queue",
   "select": "queue"
  },
  {
   "id": "random_pet_two_words",
   "kind": "exists",
   "tier": "detail",
   "quote": "a randomly generated two-word pet name",
   "select": {
    "types": [
     "random_pet"
    ],
    "where": [
     {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 2
     }
    ]
   },
   "justify": "'two-word pet name' -> random_pet with length 2"
  },
  {
   "id": "api_and_queue_named_by_pet",
   "kind": "all_of",
   "tier": "detail",
   "quote": "Use a randomly generated two-word pet name for both the API and the queue",
   "checks": [
    {
     "kind": "ref",
     "from": "api",
     "to": {
      "types": [
       "random_pet"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": "queue",
     "to": {
      "types": [
       "random_pet"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "queue_encrypted_with_cmk",
   "kind": "ref",
   "tier": "core",
   "quote": "encrypt the queue with a dedicated customer-managed KMS key",
   "from": "queue",
   "to": "kms"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "with automatic rotation",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "role_assumable_by_apigw",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM execution role assumable by API Gateway",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "apigateway.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "role",
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
        "value": "apigateway.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "role_sqs_access",
   "kind": "exists",
   "tier": "core",
   "quote": "with SQS access",
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
       "aws_iam_role_policy",
       "aws_iam_policy",
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment",
       "data.aws_iam_policy_document",
       "aws_iam_role"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)sqs:|AmazonSQS"
     }
    ]
   }
  },
  {
   "id": "role_logs_access",
   "kind": "exists",
   "tier": "detail",
   "quote": "CloudWatch Logs permissions",
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
       "aws_iam_role_policy",
       "aws_iam_policy",
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment",
       "data.aws_iam_policy_document",
       "aws_iam_role"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)logs:|CloudWatchLogs"
     }
    ]
   }
  },
  {
   "id": "connect_route_mock",
   "kind": "ref",
   "tier": "core",
   "quote": "The connect route should use a mock integration",
   "from": {
    "types": [
     "aws_apigatewayv2_route"
    ],
    "where": [
     {
      "path": [
       "route_key"
      ],
      "op": "eq",
      "value": "$connect"
     }
    ]
   },
   "to": "mock_int"
  },
  {
   "id": "mock_returns_200",
   "kind": "any_of",
   "tier": "detail",
   "quote": "returns a 200 status code",
   "checks": [
    {
     "kind": "attr",
     "select": "mock_int",
     "cond": {
      "path": [
       "request_templates"
      ],
      "op": "regex",
      "value": "\\b200\\b"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_apigatewayv2_integration_response"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "\\b200\\b"
       }
      ]
     },
     "to": "mock_int"
    }
   ]
  },
  {
   "id": "default_route_sqs_sendmessage",
   "kind": "ref",
   "tier": "core",
   "quote": "the default route should send the raw message body to the queue through a SendMessage AWS service integration",
   "from": {
    "types": [
     "aws_apigatewayv2_route"
    ],
    "where": [
     {
      "path": [
       "route_key"
      ],
      "op": "eq",
      "value": "$default"
     }
    ]
   },
   "to": "sqs_int"
  },
  {
   "id": "raw_message_body",
   "kind": "any_of",
   "tier": "detail",
   "quote": "send the raw message body",
   "justify": "the raw WebSocket message body is $input.body / route.request.body in the integration mapping",
   "checks": [
    {
     "kind": "attr",
     "select": "sqs_int",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "\\$input\\.body|\\$request\\.body|route\\.request\\.body|\\$input\\.json"
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
        "value": "aws_apigatewayv2_route"
       },
       {
        "path": [
         "properties",
         "route_key"
        ],
        "op": "eq",
        "value": "$default"
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
        "value": "aws_apigatewayv2_integration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\\$input\\.body|\\$request\\.body|route\\.request\\.body|\\$input\\.json"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "integration_targets_queue",
   "kind": "ref",
   "tier": "detail",
   "quote": "send the raw message body to the queue",
   "from": "sqs_int",
   "to": "queue"
  },
  {
   "id": "return_integration_response",
   "kind": "any_of",
   "tier": "detail",
   "quote": "return the integration response to the client",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_apigatewayv2_route_response"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_apigatewayv2_route"
      ],
      "where": [
       {
        "path": [
         "route_key"
        ],
        "op": "eq",
        "value": "$default"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_apigatewayv2_route"
      ],
      "where": [
       {
        "path": [
         "route_key"
        ],
        "op": "eq",
        "value": "$default"
       }
      ]
     },
     "cond": {
      "path": [
       "route_response_selection_expression"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_apigatewayv2_integration_response"
      ],
      "where": []
     },
     "to": "sqs_int"
    }
   ]
  },
  {
   "id": "disconnect_route_sqs",
   "kind": "ref",
   "tier": "core",
   "quote": "the disconnect route should send a fixed \"Client disconnected\" message to the same queue",
   "from": {
    "types": [
     "aws_apigatewayv2_route"
    ],
    "where": [
     {
      "path": [
       "route_key"
      ],
      "op": "eq",
      "value": "$disconnect"
     }
    ]
   },
   "to": "sqs_int"
  },
  {
   "id": "disconnect_fixed_message",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a fixed \"Client disconnected\" message",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_apigatewayv2_route"
      ],
      "where": [
       {
        "path": [
         "route_key"
        ],
        "op": "eq",
        "value": "$disconnect"
       }
      ]
     },
     "to": {
      "types": [
       "aws_apigatewayv2_integration"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)Client(%20|\\+|\\s)disconnected"
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
        "value": "aws_apigatewayv2_route"
       },
       {
        "path": [
         "properties",
         "route_key"
        ],
        "op": "eq",
        "value": "$disconnect"
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
        "value": "aws_apigatewayv2_integration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Client(%20|\\+|\\s)disconnected"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stage_dev",
   "kind": "ref",
   "tier": "core",
   "quote": "an auto-deployed stage named \"dev\"",
   "from": "stage",
   "to": "api"
  },
  {
   "id": "stage_auto_deploy",
   "kind": "attr",
   "tier": "detail",
   "quote": "an auto-deployed stage",
   "select": "stage",
   "cond": {
    "path": [
     "auto_deploy"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "stage_access_logging",
   "kind": "ref",
   "tier": "core",
   "quote": "with access logging to a CloudWatch log group",
   "from": {
    "types": [
     "aws_apigatewayv2_stage"
    ],
    "where": [
     {
      "path": [
       "access_log_settings",
       "*",
       "format"
      ],
      "op": "present"
     }
    ]
   },
   "to": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   }
  },
  {
   "id": "log_group_prefix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "under the /aws/apigateway/ prefix",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_log_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^/aws/apigateway/"
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
        "value": "aws_cloudwatch_log_group"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^/aws/apigateway/"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "log_retention_one_day",
   "kind": "attr",
   "tier": "detail",
   "quote": "retained for one day",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "retention_in_days"
    ],
    "op": "eq",
    "value": 1
   },
   "justify": "'one day' -> retention_in_days 1"
  },
  {
   "id": "endpoint_output",
   "kind": "ref",
   "tier": "detail",
   "quote": "output the full WebSocket endpoint URL including the stage name",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "stage"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
