package intent.cfn.row_229

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
  "client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
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
  "res_me": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "eq",
     "value": "me"
    }
   ]
  },
  "res_open": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "eq",
     "value": "open"
    }
   ]
  },
  "m_me": {
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
      "AuthorizationType"
     ],
     "op": "eq",
     "value": "COGNITO_USER_POOLS"
    }
   ]
  },
  "m_open": {
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
      "AuthorizationType"
     ],
     "op": "eq",
     "value": "NONE"
    }
   ]
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "perm": {
   "types": [
    "AWS::Lambda::Permission"
   ],
   "where": [
    {
     "path": [
      "Principal"
     ],
     "op": "eq",
     "value": "apigateway.amazonaws.com"
    },
    {
     "path": [
      "Action"
     ],
     "op": "eq",
     "value": "lambda:InvokeFunction"
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
  "api_body": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": [
    {
     "path": [
      "Body"
     ],
     "op": "regex",
     "value": "(?is)x-amazon-apigateway-integration"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "creates a Cognito user pool"
  },
  {
   "id": "email_auth",
   "kind": "any_of",
   "tier": "core",
   "quote": "authenticate users by email address",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "UsernameAttributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "AliasAttributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    }
   ]
  },
  {
   "id": "pw_min_length",
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
   },
   "tier": "core",
   "quote": "a minimum length of eight",
   "justify": "eight is 8"
  },
  {
   "id": "pw_classes",
   "kind": "all_of",
   "tier": "core",
   "quote": "requires uppercase, lowercase, numeric, and symbol characters",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "RequireUppercase"
      ],
      "op": "eq",
      "value": true
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
      "op": "eq",
      "value": true
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
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Policies",
       "PasswordPolicy",
       "RequireSymbols"
      ],
      "op": "eq",
      "value": true
     }
    }
   ]
  },
  {
   "id": "app_client",
   "kind": "ref",
   "from": "client",
   "to": "pool",
   "tier": "core",
   "quote": "an app client"
  },
  {
   "id": "no_secret",
   "kind": "any_of",
   "tier": "core",
   "quote": "(with no client secret)",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "password_flow",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "ExplicitAuthFlows"
    ],
    "op": "regex",
    "value": "(?i)USER_PASSWORD_AUTH|ADMIN_NO_SRP_AUTH"
   },
   "tier": "core",
   "quote": "supports username/password",
   "justify": "username/password flow is USER_PASSWORD_AUTH"
  },
  {
   "id": "refresh_flow",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "ExplicitAuthFlows"
    ],
    "op": "regex",
    "value": "(?i)REFRESH_TOKEN"
   },
   "tier": "core",
   "quote": "refresh-token based sign-in"
  },
  {
   "id": "regional_api",
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
   "quote": "a regional REST API"
  },
  {
   "id": "cognito_authorizer",
   "kind": "any_of",
   "tier": "core",
   "quote": "secured by a Cognito user pool authorizer",
   "checks": [
    {
     "kind": "ref",
     "from": "auth",
     "to": "pool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGateway::RestApi"
      ],
      "where": [
       {
        "path": [
         "Body"
        ],
        "op": "regex",
        "value": "(?i)cognito_user_pools"
       }
      ]
     },
     "to": "pool"
    }
   ]
  },
  {
   "id": "me_resource",
   "kind": "any_of",
   "tier": "core",
   "quote": "a protected GET /me endpoint",
   "checks": [
    {
     "kind": "ref",
     "from": "m_me",
     "to": "res_me"
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?is)/me\"?\\s*:\\s*\\{?\\s*\"?get\"?\\s*:"
     }
    }
   ]
  },
  {
   "id": "me_uses_authorizer",
   "kind": "any_of",
   "tier": "core",
   "quote": "a protected GET /me endpoint that only accepts requests carrying a valid access token",
   "checks": [
    {
     "kind": "ref",
     "from": "m_me",
     "to": "auth"
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?is)/me\"?\\s*:\\s*\\{?\\s*\"?get\"?\\s*:(?:[^/]|/[^o])*?security"
     }
    }
   ]
  },
  {
   "id": "open_endpoint",
   "kind": "any_of",
   "tier": "core",
   "quote": "an unauthenticated GET /open endpoint",
   "justify": "unauthenticated means AuthorizationType NONE, or no security key on the operation in an inline API definition",
   "checks": [
    {
     "kind": "ref",
     "from": "m_open",
     "to": "res_open"
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?is)/open\"?\\s*:\\s*\\{?\\s*\"?get\"?\\s*:\\s*\\{?(?:[^s]|s[^e]|se[^c])*?x-amazon-apigateway-integration"
     }
    }
   ]
  },
  {
   "id": "me_backed_by_lambda",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Both endpoints should be backed by the same Lambda function",
   "checks": [
    {
     "kind": "ref",
     "from": "m_me",
     "to": "fn"
    },
    {
     "kind": "ref",
     "from": "api_body",
     "to": "fn"
    }
   ],
   "justify": "open means AuthorizationType NONE"
  },
  {
   "id": "open_backed_by_lambda",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Both endpoints should be backed by the same Lambda function",
   "checks": [
    {
     "kind": "ref",
     "from": "m_open",
     "to": "fn"
    },
    {
     "kind": "ref",
     "from": "api_body",
     "to": "fn"
    }
   ],
   "justify": "open means AuthorizationType NONE"
  },
  {
   "id": "same_lambda",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Both endpoints should be backed by the same Lambda function",
   "checks": [
    {
     "kind": "join",
     "from": "m_me",
     "from_path": [
      "Integration",
      "Uri"
     ],
     "to": "m_open",
     "to_path": [
      "Integration",
      "Uri"
     ]
    },
    {
     "kind": "ref",
     "from": "api_body",
     "to": "fn"
    }
   ],
   "justify": "open means AuthorizationType NONE"
  },
  {
   "id": "fn_returns_claims",
   "kind": "any_of",
   "tier": "detail",
   "quote": "returns the caller's authenticated identity claims",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)claims"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "S3Bucket"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ImageUri"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "apigw_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the appropriate permission granted for API Gateway to invoke it",
   "checks": [
    {
     "kind": "ref",
     "from": "perm",
     "to": "fn"
    },
    {
     "kind": "join",
     "from": "perm",
     "from_path": [
      "FunctionName"
     ],
     "to": "fn",
     "to_path": [
      "FunctionName"
     ]
    }
   ]
  },
  {
   "id": "prod_stage",
   "kind": "any_of",
   "tier": "core",
   "quote": "deployed to a prod stage",
   "checks": [
    {
     "kind": "exists",
     "select": "stage"
    },
    {
     "kind": "exists",
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
     }
    }
   ]
  },
  {
   "id": "x_authorizer_identity_source",
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
   "id": "x_lambda_runtime",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python3\\."
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_apigateway_deployment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGateway::Deployment"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_iam_role",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
