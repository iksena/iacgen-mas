# GENERATED from specs/cfn/row_092.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_092

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "pool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "authorizer": {
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
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "mcp_res": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "eq",
     "value": "mcp"
    }
   ]
  },
  "post_method": {
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
  "options_method": {
   "types": [
    "AWS::ApiGateway::Method"
   ],
   "where": [
    {
     "path": [
      "HttpMethod"
     ],
     "op": "eq",
     "value": "OPTIONS"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "rest_api_regional",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "EndpointConfiguration",
     "Types",
     "*"
    ],
    "op": "eq",
    "value": "REGIONAL"
   },
   "tier": "core",
   "quote": "The API should be regional"
  },
  {
   "id": "cognito_user_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "The API should be secured with Cognito user pools"
  },
  {
   "id": "cognito_authorizer",
   "kind": "ref",
   "from": "authorizer",
   "to": "pool",
   "tier": "core",
   "quote": "The API should be secured with Cognito user pools"
  },
  {
   "id": "post_mcp_endpoint",
   "kind": "ref",
   "from": "post_method",
   "to": "mcp_res",
   "tier": "core",
   "quote": "include a POST endpoint at /mcp"
  },
  {
   "id": "post_protected_by_authorizer",
   "kind": "all_of",
   "tier": "core",
   "quote": "protected by the authorizer",
   "checks": [
    {
     "kind": "attr",
     "select": "post_method",
     "cond": {
      "path": [
       "AuthorizationType"
      ],
      "op": "in",
      "value": [
       "COGNITO_USER_POOLS",
       "CUSTOM"
      ]
     }
    },
    {
     "kind": "ref",
     "from": "post_method",
     "to": {
      "types": [
       "AWS::ApiGateway::Authorizer"
      ],
      "where": []
     }
    }
   ],
   "justify": "\"protected by the authorizer\": any API Gateway authorizer on the POST method; Cognito-ness is checked by cognito_authorizer"
  },
  {
   "id": "post_invokes_lambda",
   "kind": "ref",
   "from": "post_method",
   "to": "fn",
   "tier": "core",
   "quote": "a serverless Maths MCP (Model Context Protocol) server with API Gateway, Lambda"
  },
  {
   "id": "cors_options_method",
   "kind": "ref",
   "from": "options_method",
   "to": "mcp_res",
   "tier": "detail",
   "quote": "support CORS via an OPTIONS method"
  },
  {
   "id": "public_health_check_root_get",
   "kind": "exists",
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
      "value": "GET"
     },
     {
      "path": [
       "ResourceId",
       "attr"
      ],
      "op": "eq",
      "value": "RootResourceId"
     },
     {
      "path": [
       "AuthorizationType"
      ],
      "op": "eq",
      "value": "NONE"
     }
    ]
   },
   "tier": "core",
   "quote": "A health check GET endpoint on the root path should be publicly accessible without authentication",
   "justify": "\"publicly accessible without authentication\" = AuthorizationType NONE"
  },
  {
   "id": "lambda_python312",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.12"
   },
   "tier": "core",
   "quote": "use Python 3.12 runtime"
  },
  {
   "id": "lambda_timeout_memory",
   "kind": "all_of",
   "tier": "detail",
   "quote": "have a 30-second timeout, 512 MB memory",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Timeout"
      ],
      "op": "eq",
      "value": 30
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "MemorySize"
      ],
      "op": "eq",
      "value": 512
     }
    }
   ]
  },
  {
   "id": "lambda_named_after_stack",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "contains",
    "value": "stack"
   },
   "tier": "detail",
   "quote": "be named after the stack"
  },
  {
   "id": "password_policy",
   "kind": "all_of",
   "tier": "core",
   "quote": "enforce password policies (minimum 8 characters, uppercase, lowercase, numbers)",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "MinimumLength"
      ],
      "op": "eq",
      "value": 8
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "RequireUppercase"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "RequireLowercase"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "RequireNumbers"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "email_auto_verify",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "AutoVerifiedAttributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   },
   "tier": "detail",
   "quote": "allow email auto-verification"
  },
  {
   "id": "email_as_username",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "UsernameAttributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   },
   "tier": "detail",
   "quote": "use email as username"
  },
  {
   "id": "app_client",
   "kind": "ref",
   "from": "client",
   "to": "pool",
   "tier": "core",
   "quote": "The app client should allow password-based auth flows"
  },
  {
   "id": "password_auth_flow",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "ExplicitAuthFlows",
     "*"
    ],
    "op": "regex",
    "value": "(?i)^(ALLOW_)?(USER_PASSWORD_AUTH|ADMIN_NO_SRP_AUTH|ADMIN_USER_PASSWORD_AUTH)$"
   },
   "tier": "detail",
   "quote": "allow password-based auth flows"
  },
  {
   "id": "accesstoken_validity_1h",
   "kind": "any_of",
   "tier": "detail",
   "quote": "1-hour access/id token validity",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "days"
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 60
       },
       {
        "path": [
         "TokenValidityUnits",
         "AccessToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    }
   ],
   "justify": "1 hour = 1 (hours, the default unit) or 60 minutes"
  },
  {
   "id": "idtoken_validity_1h",
   "kind": "any_of",
   "tier": "detail",
   "quote": "1-hour access/id token validity",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "IdTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "days"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "IdTokenValidity"
        ],
        "op": "eq",
        "value": 60
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    }
   ],
   "justify": "1 hour = 1 (hours, the default unit) or 60 minutes"
  },
  {
   "id": "refresh_token_validity_30d",
   "kind": "any_of",
   "tier": "detail",
   "quote": "30-day refresh token validity",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 30
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "minutes"
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "hours"
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "none_eq",
        "value": "seconds"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Cognito::UserPoolClient"
      ],
      "where": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 720
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "hours"
       }
      ]
     }
    }
   ],
   "justify": "30 days = 30 (days, the default unit) or 720 hours"
  },
  {
   "id": "default_resource_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "UserPoolName = 'maths-mcp-users', AppClientName = 'maths-mcp-client'",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "UserPoolName"
      ],
      "op": "eq",
      "value": "maths-mcp-users"
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "ClientName"
      ],
      "op": "eq",
      "value": "maths-mcp-client"
     }
    }
   ]
  },
  {
   "id": "deployment_stage_dev",
   "kind": "any_of",
   "tier": "detail",
   "quote": "DeploymentStage = 'dev'",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "StageName"
      ],
      "op": "eq",
      "value": "dev"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Stage"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "StageName"
      ],
      "op": "eq",
      "value": "dev"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
