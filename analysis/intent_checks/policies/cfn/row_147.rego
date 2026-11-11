package intent.cfn.row_147

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ws_api": {
   "types": [
    "AWS::ApiGatewayV2::Api"
   ],
   "where": [
    {
     "path": [
      "ProtocolType"
     ],
     "op": "eq",
     "value": "WEBSOCKET"
    }
   ]
  },
  "r_connect": {
   "types": [
    "AWS::ApiGatewayV2::Route"
   ],
   "where": [
    {
     "path": [
      "RouteKey"
     ],
     "op": "eq",
     "value": "$connect"
    }
   ]
  },
  "r_default": {
   "types": [
    "AWS::ApiGatewayV2::Route"
   ],
   "where": [
    {
     "path": [
      "RouteKey"
     ],
     "op": "eq",
     "value": "$default"
    }
   ]
  },
  "r_disconnect": {
   "types": [
    "AWS::ApiGatewayV2::Route"
   ],
   "where": [
    {
     "path": [
      "RouteKey"
     ],
     "op": "eq",
     "value": "$disconnect"
    }
   ]
  },
  "i_put": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": [
    {
     "path": [
      "IntegrationUri"
     ],
     "op": "regex",
     "value": "(?i)dynamodb.*(putitem|updateitem)"
    }
   ]
  },
  "i_delete": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": [
    {
     "path": [
      "IntegrationUri"
     ],
     "op": "regex",
     "value": "(?i)dynamodb.*deleteitem"
    }
   ]
  },
  "i_lambda": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": [
    {
     "path": [
      "IntegrationType"
     ],
     "op": "eq",
     "value": "AWS_PROXY"
    }
   ]
  },
  "table": {
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
  "stage": {
   "types": [
    "AWS::ApiGatewayV2::Stage"
   ],
   "where": []
  },
  "deployment": {
   "types": [
    "AWS::ApiGatewayV2::Deployment"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "apigw_role": {
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
     "value": "apigateway.amazonaws.com"
    }
   ]
  },
  "api": {
   "types": [
    "AWS::ApiGatewayV2::Api"
   ],
   "where": []
  },
  "i_lambda_uri": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": [
    {
     "path": [
      "IntegrationUri"
     ],
     "op": "regex",
     "value": "(?i):lambda:path/"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "ws_api",
   "tier": "core",
   "kind": "exists",
   "select": "ws_api",
   "quote": "creates a WebSocket API"
  },
  {
   "id": "route_connect",
   "tier": "core",
   "kind": "exists",
   "select": "r_connect",
   "quote": "a $connect route"
  },
  {
   "id": "route_default",
   "tier": "core",
   "kind": "exists",
   "select": "r_default",
   "quote": "a $default route"
  },
  {
   "id": "route_disconnect",
   "tier": "core",
   "kind": "exists",
   "select": "r_disconnect",
   "quote": "a $disconnect route"
  },
  {
   "id": "table",
   "tier": "core",
   "kind": "exists",
   "select": "table",
   "quote": "stores their identifiers in a DynamoDB table"
  },
  {
   "id": "ttl",
   "tier": "core",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "TimeToLiveSpecification",
     "Enabled"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "The DynamoDB table should have time-to-live enabled for automatic cleanup of expired sessions"
  },
  {
   "id": "connect_integration",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "r_connect",
     "to": "i_put"
    },
    {
     "kind": "ref",
     "from": "r_connect",
     "to": "i_lambda"
    },
    {
     "kind": "ref",
     "from": "r_connect",
     "to": "i_lambda_uri"
    }
   ],
   "quote": "a $connect route that captures new client connections and stores their identifiers in a DynamoDB table",
   "justify": "the route writes to DynamoDB directly or through a Lambda (AWS_PROXY) integration"
  },
  {
   "id": "connect_table_write",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "i_put",
     "to": "table"
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": "table"
    }
   ],
   "quote": "stores their identifiers in a DynamoDB table"
  },
  {
   "id": "disconnect_integration",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "r_disconnect",
     "to": "i_delete"
    },
    {
     "kind": "ref",
     "from": "r_disconnect",
     "to": "i_lambda"
    },
    {
     "kind": "ref",
     "from": "r_disconnect",
     "to": "i_lambda_uri"
    }
   ],
   "quote": "a $disconnect route that removes disconnected clients from the session table",
   "justify": "the route deletes from DynamoDB directly or through a Lambda integration"
  },
  {
   "id": "disconnect_table_write",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "i_delete",
     "to": "table"
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": "table"
    }
   ],
   "quote": "removes disconnected clients from the session table"
  },
  {
   "id": "default_lambda_fn",
   "tier": "core",
   "kind": "exists",
   "select": "fn",
   "quote": "echoes incoming messages back to clients using a Lambda function"
  },
  {
   "id": "default_to_lambda",
   "tier": "core",
   "quote": "a $default route that echoes incoming messages back to clients using a Lambda function",
   "justify": "Lambda integrations are AWS_PROXY integrations",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "r_default",
     "to": "i_lambda"
    },
    {
     "kind": "ref",
     "from": "r_default",
     "to": "i_lambda_uri"
    }
   ]
  },
  {
   "id": "default_echoes",
   "tier": "detail",
   "quote": "echoes incoming messages back to clients",
   "justify": "an echo returns the message body through PostToConnection or the route response",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)post_?to_?connection|body.{0,40}(event|message|data)"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "S3Key"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "stage_name",
   "tier": "core",
   "kind": "attr",
   "select": "stage",
   "cond": {
    "path": [
     "StageName"
    ],
    "op": "eq",
    "value": "api"
   },
   "quote": "Configure the API stage with a default name of 'api'"
  },
  {
   "id": "perm_write",
   "tier": "core",
   "quote": "IAM permissions for API Gateway to write and delete items from the session tracking table",
   "justify": "write items = PutItem (or UpdateItem)",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "apigw_role",
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
      "value": "dynamodb:PutItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "apigw_role",
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
        "value": "dynamodb:PutItem"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "apigw_role",
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
      "value": "dynamodb:UpdateItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "apigw_role",
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
        "value": "dynamodb:UpdateItem"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_delete",
   "tier": "core",
   "quote": "IAM permissions for API Gateway to write and delete items from the session tracking table",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "apigw_role",
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
      "value": "dynamodb:DeleteItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "apigw_role",
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
        "value": "dynamodb:DeleteItem"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "perm_on_session_table",
   "tier": "detail",
   "quote": "from the session tracking table",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "apigw_role",
     "to": "table"
    },
    {
     "kind": "attr",
     "select": "apigw_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":table/"
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
        "value": "dynamodb:DeleteItem"
       }
      ]
     },
     "to": "table"
    }
   ]
  },
  {
   "id": "x_integ_role",
   "tier": "extra",
   "kind": "ref",
   "from": "i_put",
   "to": "apigw_role"
  },
  {
   "id": "x_apigw_trust",
   "tier": "extra",
   "kind": "exists",
   "select": "apigw_role"
  },
  {
   "id": "x_billing",
   "tier": "extra",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   }
  },
  {
   "id": "x_runtime",
   "tier": "extra",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^nodejs"
   }
  },
  {
   "id": "x_stage_deployment",
   "tier": "extra",
   "kind": "ref",
   "from": "stage",
   "to": "deployment"
  },
  {
   "id": "x_fn_trust",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "lambda.amazonaws.com"
   }
  },
  {
   "id": "extra_type_aws_apigatewayv2_integrationresponse",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGatewayV2::IntegrationResponse"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_apigatewayv2_routeresponse",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGatewayV2::RouteResponse"
    ],
    "where": []
   }
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
