package intent.cfn.row_106

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "domain": {
   "types": [
    "AWS::Cognito::UserPoolDomain"
   ],
   "where": []
  },
  "rs": {
   "types": [
    "AWS::Cognito::UserPoolResourceServer"
   ],
   "where": [
    {
     "path": [
      "Identifier"
     ],
     "op": "eq",
     "value": "petstore-api.example.com"
    }
   ]
  },
  "client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "AllowedOAuthFlows",
      "*"
     ],
     "op": "eq",
     "value": "client_credentials"
    }
   ]
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "AWS::KMS::Alias"
   ],
   "where": []
  },
  "api": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "auth": {
   "types": [
    "AWS::ApiGateway::Authorizer"
   ],
   "where": [
    {
     "path": [
      "Type"
     ],
     "op": "eq",
     "value": "COGNITO_USER_POOLS"
    }
   ]
  },
  "post": {
   "types": [
    "AWS::ApiGateway::Method"
   ],
   "where": [
    {
     "path": [
      "HttpMethod"
     ],
     "op": "eq",
     "value": "POST"
    }
   ]
  },
  "stage": {
   "types": [
    "AWS::ApiGateway::Stage"
   ],
   "where": [
    {
     "path": [
      "StageName"
     ],
     "op": "eq",
     "value": "prod"
    }
   ]
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "creates a Cognito User Pool"
  },
  {
   "id": "user_pool_default_name",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "UserPoolName"
    ],
    "op": "eq",
    "value": "MyServerlessLandUserPool"
   },
   "tier": "core",
   "quote": "defaulting to \"MyServerlessLandUserPool\""
  },
  {
   "id": "user_pool_name_parameter",
   "kind": "join",
   "tier": "detail",
   "quote": "name configurable via parameter, defaulting to \"MyServerlessLandUserPool\"",
   "from": "pool",
   "from_path": [
    "UserPoolName"
   ],
   "to": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "to_path": [
    "default"
   ]
  },
  {
   "id": "user_pool_domain",
   "kind": "ref",
   "from": "domain",
   "to": "pool",
   "tier": "core",
   "quote": "with a domain using a unique suffix derived from the stack ID"
  },
  {
   "id": "domain_stack_id_suffix",
   "kind": "attr",
   "select": "domain",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "regex",
    "value": "\\bid\\b"
   },
   "tier": "detail",
   "quote": "a domain using a unique suffix derived from the stack ID",
   "justify": "a value taken from the stack ID keeps its last segment, which the normaliser renders as the token id"
  },
  {
   "id": "resource_server",
   "kind": "ref",
   "from": "rs",
   "to": "pool",
   "tier": "core",
   "quote": "a resource server exposing a \"domestic.read\" scope under the identifier \"petstore-api.example.com\""
  },
  {
   "id": "resource_server_scope",
   "kind": "attr",
   "select": "rs",
   "cond": {
    "path": [
     "Scopes",
     "*",
     "ScopeName"
    ],
    "op": "eq",
    "value": "domestic.read"
   },
   "tier": "core",
   "quote": "a resource server exposing a \"domestic.read\" scope"
  },
  {
   "id": "m2m_client_credentials",
   "kind": "ref",
   "from": "client",
   "to": "pool",
   "tier": "core",
   "quote": "a machine-to-machine app client"
  },
  {
   "id": "m2m_client_secret",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with a generated secret"
  },
  {
   "id": "m2m_client_scope",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "AllowedOAuthScopes",
     "*"
    ],
    "op": "regex",
    "value": "domestic\\.read"
   },
   "tier": "detail",
   "quote": "using the client credentials OAuth flow",
   "justify": "the client credentials flow needs a custom scope and domestic.read is the only one the prompt defines"
  },
  {
   "id": "m2m_client_default_name",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "ClientName"
    ],
    "op": "eq",
    "value": "MyWebClient"
   },
   "tier": "core",
   "quote": "defaulting to \"MyWebClient\""
  },
  {
   "id": "m2m_client_name_parameter",
   "kind": "join",
   "from": "client",
   "from_path": [
    "ClientName"
   ],
   "to": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "to_path": [
    "default"
   ],
   "tier": "detail",
   "quote": "name configurable, defaulting to \"MyWebClient\""
  },
  {
   "id": "callback_urls",
   "checks": [
    {
     "kind": "join",
     "from": "client",
     "from_path": [
      "CallbackURLs",
      "*"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
     "from": "client",
     "from_path": [
      "CallbackURLs",
      "*"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default",
      "*"
     ]
    }
   ],
   "kind": "any_of",
   "tier": "detail",
   "quote": "configurable callback and logout URLs"
  },
  {
   "id": "logout_urls",
   "checks": [
    {
     "kind": "join",
     "from": "client",
     "from_path": [
      "LogoutURLs",
      "*"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
     "from": "client",
     "from_path": [
      "LogoutURLs",
      "*"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default",
      "*"
     ]
    }
   ],
   "kind": "any_of",
   "tier": "detail",
   "quote": "configurable callback and logout URLs"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "key",
   "tier": "core",
   "quote": "a customer-managed KMS key"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with key rotation enabled"
  },
  {
   "id": "kms_root_full_access",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "KeyPolicy",
     "Statement",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Effect"
      ],
      "op": "eq",
      "value": "Allow"
     },
     {
      "path": [
       "Principal",
       "AWS",
       "*"
      ],
      "op": "regex",
      "value": ":root$|^[0-9]{12}$"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:*"
     }
    ]
   },
   "tier": "core",
   "quote": "allows the account root full KMS access",
   "justify": "an account-ID principal is the same as the account root; kms:* or * is full KMS access"
  },
  {
   "id": "kms_events_generate_data_key",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "KeyPolicy",
     "Statement",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Effect"
      ],
      "op": "eq",
      "value": "Allow"
     },
     {
      "path": [
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "events.amazonaws.com"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:GenerateDataKey"
     }
    ]
   },
   "tier": "core",
   "quote": "allows the EventBridge service to generate data keys and decrypt"
  },
  {
   "id": "kms_events_decrypt",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "KeyPolicy",
     "Statement",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Effect"
      ],
      "op": "eq",
      "value": "Allow"
     },
     {
      "path": [
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "events.amazonaws.com"
     },
     {
      "path": [
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "kms:Decrypt"
     }
    ]
   },
   "tier": "core",
   "quote": "allows the EventBridge service to generate data keys and decrypt"
  },
  {
   "id": "kms_alias",
   "kind": "ref",
   "from": "alias",
   "to": "key",
   "tier": "core",
   "quote": "along with an alias for that key"
  },
  {
   "id": "rest_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "an API Gateway REST API"
  },
  {
   "id": "cognito_authorizer",
   "kind": "ref",
   "from": "auth",
   "to": "pool",
   "tier": "core",
   "quote": "secured by a Cognito User Pool authorizer using the created user pool"
  },
  {
   "id": "post_method_authorized",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::ApiGateway::Method"
    ],
    "where": [
     {
      "path": [
       "HttpMethod"
      ],
      "op": "eq",
      "value": "POST"
     },
     {
      "path": [
       "AuthorizationType"
      ],
      "op": "eq",
      "value": "COGNITO_USER_POOLS"
     }
    ]
   },
   "cond": {
    "path": [
     "AuthorizationScopes",
     "*"
    ],
    "op": "regex",
    "value": "domestic\\.read"
   },
   "tier": "core",
   "quote": "a POST method requiring the \"domestic.read\" scope"
  },
  {
   "id": "post_method_uses_authorizer",
   "kind": "ref",
   "from": "post",
   "to": "auth",
   "tier": "core",
   "quote": "secured by a Cognito User Pool authorizer"
  },
  {
   "id": "post_http_backend",
   "kind": "attr",
   "select": "post",
   "cond": {
    "path": [
     "Integration",
     "Uri"
    ],
    "op": "regex",
    "value": "^https?://"
   },
   "tier": "detail",
   "quote": "proxies to a public sample backend endpoint",
   "justify": "a public backend endpoint is an http(s) URL"
  },
  {
   "id": "stage_prod",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "stage",
     "to": "api"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "eq",
        "value": "prod"
       }
      ]
     },
     "to": "api"
    }
   ],
   "tier": "core",
   "quote": "deployed to a stage named \"prod\""
  },
  {
   "id": "stage_info_logging",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "stage",
     "cond": {
      "path": [
       "MethodSettings",
       "*",
       "LoggingLevel"
      ],
      "op": "eq",
      "value": "INFO"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "eq",
        "value": "prod"
       }
      ]
     },
     "cond": {
      "path": [
       "StageDescription",
       "MethodSettings",
       "*",
       "LoggingLevel"
      ],
      "op": "eq",
      "value": "INFO"
     }
    }
   ],
   "tier": "detail",
   "quote": "INFO-level logging"
  },
  {
   "id": "stage_data_trace",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "stage",
     "cond": {
      "path": [
       "MethodSettings",
       "*",
       "DataTraceEnabled"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "eq",
        "value": "prod"
       }
      ]
     },
     "cond": {
      "path": [
       "StageDescription",
       "MethodSettings",
       "*",
       "DataTraceEnabled"
      ],
      "op": "truthy"
     }
    }
   ],
   "tier": "detail",
   "quote": "full data tracing enabled"
  },
  {
   "id": "out_user_pool_arn",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)\"attr\": \"Arn\"|arn:"
     }
    ]
   },
   "to": "pool",
   "tier": "detail",
   "quote": "Output the user pool ARN"
  },
  {
   "id": "out_api_url",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "execute-api"
   },
   "tier": "detail",
   "quote": "the API endpoint URL",
   "justify": "an API Gateway endpoint URL contains execute-api"
  },
  {
   "id": "out_client_id",
   "kind": "ref",
   "from": "out",
   "to": "client",
   "tier": "detail",
   "quote": "the app client ID"
  },
  {
   "id": "out_kms_arn",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)\"attr\": \"Arn\"|arn:"
     }
    ]
   },
   "to": "key",
   "tier": "detail",
   "quote": "the KMS key ARN"
  },
  {
   "id": "out_token_endpoint",
   "kind": "attr",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)/oauth2?/token"
   },
   "tier": "detail",
   "quote": "the user pool domain's OAuth token endpoint",
   "justify": "the token endpoint path of a Cognito domain"
  },
  {
   "id": "x_authorizer_header",
   "kind": "attr",
   "select": "auth",
   "cond": {
    "path": [
     "IdentitySource"
    ],
    "op": "eq",
    "value": "method.request.header.Authorization"
   },
   "tier": "extra"
  },
  {
   "id": "x_oauth_flow_enabled",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "AllowedOAuthFlowsUserPoolClient"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
