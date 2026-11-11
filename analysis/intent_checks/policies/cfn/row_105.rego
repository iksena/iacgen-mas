package intent.cfn.row_105

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
     "value": "api"
    }
   ]
  },
  "web": {
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
     "value": "code"
    }
   ]
  },
  "m2m": {
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
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "select": "pool",
   "tier": "core",
   "quote": "creates a self-service Cognito user pool"
  },
  {
   "id": "self_signup_enabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "AdminCreateUserConfig",
       "AllowAdminCreateUserOnly"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "AdminCreateUserConfig",
       "AllowAdminCreateUserOnly"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "enabling self-service signup",
   "justify": "self-service signup means admin-only user creation is not enabled"
  },
  {
   "id": "signup_with_email",
   "kind": "any_of",
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
   ],
   "tier": "core",
   "quote": "users can sign up using their email address"
  },
  {
   "id": "email_verification",
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
   "tier": "core",
   "quote": "verify themselves without any admin intervention by enabling self-service signup with email verification"
  },
  {
   "id": "hosted_ui_domain",
   "kind": "ref",
   "from": "domain",
   "to": "pool",
   "tier": "core",
   "quote": "a hosted UI domain for signup and login pages"
  },
  {
   "id": "resource_server_api",
   "kind": "ref",
   "from": "rs",
   "to": "pool",
   "tier": "core",
   "quote": "a resource server with identifier \"api\""
  },
  {
   "id": "resource_server_scopes",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [
       "Scopes",
       "*",
       "ScopeName"
      ],
      "op": "eq",
      "value": "mcp"
     }
    },
    {
     "kind": "attr",
     "select": "rs",
     "cond": {
      "path": [
       "Scopes",
       "*",
       "ScopeName"
      ],
      "op": "eq",
      "value": "gateway"
     }
    }
   ],
   "tier": "core",
   "quote": "custom scopes named \"mcp\" and \"gateway\""
  },
  {
   "id": "web_client_code_flow",
   "kind": "ref",
   "from": "web",
   "to": "pool",
   "tier": "core",
   "quote": "a public web client that supports authorization code with PKCE"
  },
  {
   "id": "web_client_public",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "a public web client"
  },
  {
   "id": "web_explicit_auth_flows",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "ExplicitAuthFlows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_)?USER_PASSWORD_AUTH$"
     }
    },
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "ExplicitAuthFlows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_)?USER_SRP_AUTH$"
     }
    }
   ],
   "tier": "core",
   "quote": "explicit auth flows for USER_PASSWORD_AUTH and USER_SRP_AUTH for programmatic testing"
  },
  {
   "id": "web_access_id_60min",
   "kind": "any_of",
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 60
       },
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
         "AccessToken"
        ],
        "op": "eq",
        "value": "minutes"
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
     },
     "min": 1
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
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
         "AccessToken"
        ],
        "op": "eq",
        "value": "hours"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "hours"
       }
      ]
     },
     "min": 1
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
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
         "AccessToken"
        ],
        "op": "absent"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "absent"
       }
      ]
     },
     "min": 1
    }
   ],
   "tier": "core",
   "quote": "token validity set to 60 minutes for access and ID tokens and 30 days for refresh tokens",
   "justify": "60 minutes may also be written as 1 hour"
  },
  {
   "id": "web_refresh_30days",
   "kind": "any_of",
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
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
        "op": "eq",
        "value": "days"
       }
      ]
     },
     "min": 1
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
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
        "op": "absent"
       }
      ]
     },
     "min": 1
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "code"
       },
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
     },
     "min": 1
    }
   ],
   "tier": "core",
   "quote": "token validity set to 60 minutes for access and ID tokens and 30 days for refresh tokens",
   "justify": "30 days may also be written as 720 hours"
  },
  {
   "id": "m2m_two_clients_client_credentials",
   "kind": "exists",
   "select": "m2m",
   "min": 2,
   "tier": "core",
   "quote": "two separate machine-to-machine clients that use the client credentials grant",
   "justify": "two clients"
  },
  {
   "id": "m2m_gateway_scope",
   "kind": "exists",
   "select": {
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
     },
     {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "regex",
      "value": "(?i)/gateway$"
     },
     {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "none_eq",
      "value": "api/mcp"
     }
    ]
   },
   "tier": "core",
   "quote": "appropriate custom scopes for gateway and MCP server authentication",
   "justify": "identifier api + the stated scope name; separate clients, so neither holds the other's scope"
  },
  {
   "id": "m2m_mcp_scope",
   "kind": "exists",
   "select": {
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
     },
     {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "regex",
      "value": "(?i)/mcp$"
     },
     {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "none_eq",
      "value": "api/gateway"
     }
    ]
   },
   "tier": "core",
   "quote": "appropriate custom scopes for gateway and MCP server authentication",
   "justify": "identifier api + the stated scope name; separate clients, so neither holds the other's scope"
  },
  {
   "id": "m2m_generated_secret",
   "kind": "exists",
   "select": {
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
     },
     {
      "path": [
       "GenerateSecret"
      ],
      "op": "truthy"
     }
    ]
   },
   "min": 2,
   "tier": "core",
   "quote": "each with a generated client secret and token validity of 60 minutes for access and ID tokens and 1 day for refresh tokens",
   "justify": "each of the two clients"
  },
  {
   "id": "m2m_access_id_60min",
   "kind": "any_of",
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 60
       },
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
         "AccessToken"
        ],
        "op": "eq",
        "value": "minutes"
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
     },
     "min": 2
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
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
         "AccessToken"
        ],
        "op": "eq",
        "value": "hours"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "hours"
       }
      ]
     },
     "min": 2
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "AccessTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
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
         "AccessToken"
        ],
        "op": "absent"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "absent"
       }
      ]
     },
     "min": 2
    }
   ],
   "tier": "core",
   "quote": "each with a generated client secret and token validity of 60 minutes for access and ID tokens and 1 day for refresh tokens",
   "justify": "60 minutes may also be written as 1 hour; each of the two clients"
  },
  {
   "id": "m2m_refresh_1day",
   "kind": "any_of",
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "days"
       }
      ]
     },
     "min": 2
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "absent"
       }
      ]
     },
     "min": 2
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
         "AllowedOAuthFlows",
         "*"
        ],
        "op": "eq",
        "value": "client_credentials"
       },
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 24
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
     },
     "min": 2
    }
   ],
   "tier": "core",
   "quote": "each with a generated client secret and token validity of 60 minutes for access and ID tokens and 1 day for refresh tokens",
   "justify": "1 day may also be written as 24 hours; each of the two clients"
  },
  {
   "id": "callback_logout_params",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "CommaDelimitedList"
     }
    ]
   },
   "min": 2,
   "tier": "detail",
   "quote": "accept comma-delimited parameters for callback and logout URLs",
   "justify": "one parameter for callback URLs and one for logout URLs"
  },
  {
   "id": "localhost_defaults",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "CommaDelimitedList"
     },
     {
      "path": [
       "default",
       "*"
      ],
      "op": "regex",
      "value": "(?i)localhost"
     }
    ]
   },
   "min": 2,
   "tier": "detail",
   "quote": "sensible localhost defaults",
   "justify": "both parameters default to localhost URLs"
  },
  {
   "id": "web_client_urls",
   "tier": "detail",
   "kind": "join",
   "from": "web",
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
   ],
   "quote": "accept comma-delimited parameters for callback and logout URLs"
  },
  {
   "id": "web_client_logout_urls",
   "tier": "detail",
   "kind": "join",
   "from": "web",
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
   ],
   "quote": "accept comma-delimited parameters for callback and logout URLs"
  },
  {
   "id": "x_web_scopes",
   "kind": "attr",
   "select": "web",
   "cond": {
    "path": [
     "AllowedOAuthScopes",
     "*"
    ],
    "op": "eq",
    "value": "openid"
   },
   "tier": "extra"
  },
  {
   "id": "x_oauth_flows_enabled",
   "kind": "attr",
   "select": "m2m",
   "cond": {
    "path": [
     "AllowedOAuthFlowsUserPoolClient"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "tier": "extra"
  },
  {
   "id": "x_web_secret_false_revocation",
   "kind": "attr",
   "select": "web",
   "cond": {
    "path": [
     "EnableTokenRevocation"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  },
  {
   "id": "x_pool_mfa_off",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "MfaConfiguration"
      ],
      "op": "eq",
      "value": "OFF"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "MfaConfiguration"
      ],
      "op": "absent"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
