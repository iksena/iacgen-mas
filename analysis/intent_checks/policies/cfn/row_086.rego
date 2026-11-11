package intent.cfn.row_086

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
  "cl": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "dom": {
   "types": [
    "AWS::Cognito::UserPoolDomain"
   ],
   "where": []
  },
  "idp": {
   "types": [
    "AWS::Cognito::UserPoolIdentityProvider"
   ],
   "where": []
  },
  "secret": {
   "types": [
    "AWS::SecretsManager::Secret"
   ],
   "where": []
  },
  "google_idp": {
   "types": [
    "AWS::Cognito::UserPoolIdentityProvider"
   ],
   "where": [
    {
     "path": [
      "ProviderType"
     ],
     "op": "eq",
     "value": "Google"
    }
   ]
  },
  "oauth_cl": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "AllowedOAuthFlows",
      "*"
     ],
     "op": "in",
     "value": [
      "code",
      "implicit"
     ]
    }
   ]
  },
  "custom_google_idp": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "regex",
     "value": "(?i)^custom::.*(google|identity.?provider|idp)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an Amazon Cognito user pool",
   "select": "pool"
  },
  {
   "id": "verify_emails",
   "kind": "attr",
   "tier": "core",
   "quote": "The user pool should verify user emails",
   "select": "pool",
   "cond": {
    "path": [
     "AutoVerifiedAttributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   }
  },
  {
   "id": "email_as_username",
   "kind": "attr",
   "tier": "core",
   "quote": "use email as the username",
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
   "id": "required_mutable_attrs",
   "kind": "all_of",
   "tier": "core",
   "quote": "collect email, given name, and family name as required, mutable attributes",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "email"
       },
       {
        "path": [
         "Required"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "Mutable"
        ],
        "op": "none_eq",
        "value": "false"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "given_name"
       },
       {
        "path": [
         "Required"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "Mutable"
        ],
        "op": "none_eq",
        "value": "false"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "family_name"
       },
       {
        "path": [
         "Required"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "Mutable"
        ],
        "op": "none_eq",
        "value": "false"
       }
      ]
     }
    }
   ],
   "justify": "mutable means not set to false (the CloudFormation default is mutable)"
  },
  {
   "id": "lambda_triggers",
   "kind": "all_of",
   "tier": "core",
   "quote": "it should trigger custom Lambda functions, created as part of the same stack, for post-authentication, post-confirmation, and pre-sign-up processing",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "LambdaConfig",
       "PostAuthentication"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "LambdaConfig",
       "PostConfirmation"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "LambdaConfig",
       "PreSignUp"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "app_client",
   "kind": "exists",
   "tier": "core",
   "quote": "provision an app client for the frontend",
   "select": "cl"
  },
  {
   "id": "client_in_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "provision an app client for the frontend",
   "from": "cl",
   "to": "pool"
  },
  {
   "id": "oauth_flows",
   "kind": "all_of",
   "tier": "core",
   "quote": "supports the standard OAuth authorization code and implicit flows",
   "checks": [
    {
     "kind": "attr",
     "select": "cl",
     "cond": {
      "path": [
       "AllowedOAuthFlows",
       "*"
      ],
      "op": "eq",
      "value": "code"
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "AllowedOAuthFlows",
       "*"
      ],
      "op": "eq",
      "value": "implicit"
     }
    }
   ]
  },
  {
   "id": "oauth_scopes",
   "kind": "all_of",
   "tier": "core",
   "quote": "with email, openid, and profile scopes",
   "checks": [
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    },
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "eq",
      "value": "openid"
     }
    },
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "eq",
      "value": "profile"
     }
    }
   ]
  },
  {
   "id": "refresh_token_30_days",
   "kind": "any_of",
   "tier": "core",
   "quote": "a refresh token validity of 30 days",
   "checks": [
    {
     "kind": "attr",
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
        "op": "in",
        "value": [
         "code",
         "implicit"
        ]
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
        "value": "minutes"
       }
      ]
     },
     "cond": {
      "path": [
       "RefreshTokenValidity"
      ],
      "op": "eq",
      "value": 30
     }
    },
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "RefreshTokenValidity"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "30 counts only in days, the default unit; an omitted validity defaults to 30 days"
  },
  {
   "id": "callback_and_logout_urls",
   "kind": "all_of",
   "tier": "detail",
   "quote": "callback and logout URLs based on a configurable frontend domain name",
   "checks": [
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "CallbackURLs",
       "*"
      ],
      "op": "regex",
      "value": "^https?://"
     }
    },
    {
     "kind": "attr",
     "select": "oauth_cl",
     "cond": {
      "path": [
       "LogoutURLs",
       "*"
      ],
      "op": "regex",
      "value": "^https?://"
     }
    }
   ],
   "justify": "URLs on a frontend domain are web URLs"
  },
  {
   "id": "frontend_domain_parameter",
   "kind": "exists",
   "tier": "detail",
   "quote": "based on a configurable frontend domain name",
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
      "value": "(?i)(front.?end|(web|app|site).?(domain|url))"
     }
    ]
   },
   "justify": "configurable means a template parameter; its name states the frontend, since the Hosted UI prefix is also a domain"
  },
  {
   "id": "hosted_ui_domain",
   "kind": "attr",
   "tier": "core",
   "quote": "configure a Cognito Hosted UI using a Cognito-provided domain prefix",
   "select": "dom",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "regex",
    "value": "^[a-zA-Z0-9-]+$"
   },
   "justify": "a Cognito domain prefix has no dots, unlike a custom domain name"
  },
  {
   "id": "domain_in_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "configure a Cognito Hosted UI",
   "from": "dom",
   "to": "pool"
  },
  {
   "id": "no_custom_domain",
   "kind": "attr",
   "tier": "core",
   "quote": "rather than a custom domain",
   "select": "dom",
   "quantifier": "all",
   "cond": {
    "path": [
     "CustomDomainConfig"
    ],
    "op": "absent"
   }
  },
  {
   "id": "google_provider",
   "kind": "any_of",
   "tier": "core",
   "quote": "add a Google identity provider to the user pool",
   "checks": [
    {
     "kind": "exists",
     "select": "google_idp"
    },
    {
     "kind": "exists",
     "select": "custom_google_idp"
    }
   ],
   "justify": "a custom resource whose type names the Google provider also creates it"
  },
  {
   "id": "google_provider_in_pool",
   "kind": "any_of",
   "tier": "detail",
   "quote": "add a Google identity provider to the user pool",
   "checks": [
    {
     "kind": "ref",
     "from": "google_idp",
     "to": "pool"
    },
    {
     "kind": "ref",
     "from": "custom_google_idp",
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
        "value": "AWS::Cognito::UserPool"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "google_scopes",
   "kind": "any_of",
   "tier": "detail",
   "quote": "using the standard profile, email, and openid scopes for Google sign-in",
   "checks": [
    {
     "kind": "attr",
     "select": "google_idp",
     "cond": {
      "path": [
       "ProviderDetails",
       "authorize_scopes"
      ],
      "op": "regex",
      "value": "(?i)(profile\\W+email\\W+openid|profile\\W+openid\\W+email|email\\W+profile\\W+openid|email\\W+openid\\W+profile|openid\\W+profile\\W+email|openid\\W+email\\W+profile)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)authorize_scopes\\W+(profile\\W+email\\W+openid|profile\\W+openid\\W+email|email\\W+profile\\W+openid|email\\W+openid\\W+profile|openid\\W+profile\\W+email|openid\\W+email\\W+profile)"
     }
    }
   ],
   "justify": "the three scopes in any order; a custom-resource provider sets them in its function code"
  },
  {
   "id": "secrets_manager_secret",
   "kind": "exists",
   "tier": "core",
   "quote": "storing the Google OAuth client ID and client secret in AWS Secrets Manager as part of the same stack",
   "select": "secret"
  },
  {
   "id": "secret_holds_google_credentials",
   "kind": "any_of",
   "tier": "detail",
   "quote": "storing the Google OAuth client ID and client secret in AWS Secrets Manager",
   "checks": [
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "SecretString"
      ],
      "op": "regex",
      "value": "(?is)client.?id.*client.?secret|client.?secret.*client.?id"
     }
    },
    {
     "kind": "attr",
     "select": "secret",
     "cond": {
      "path": [
       "GenerateSecretString",
       "SecretStringTemplate"
      ],
      "op": "regex",
      "value": "(?is)client.?id.*client.?secret|client.?secret.*client.?id"
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "AWS::SecretsManager::Secret"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)client.?(id|secret)"
       }
      ]
     }
    }
   ],
   "justify": "the secret holds a client id and a client secret, in one secret or in two"
  },
  {
   "id": "x_client_oauth_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "cl",
   "cond": {
    "path": [
     "AllowedOAuthFlowsUserPoolClient"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_client_google_supported",
   "kind": "attr",
   "tier": "extra",
   "select": "cl",
   "cond": {
    "path": [
     "SupportedIdentityProviders",
     "*"
    ],
    "op": "eq",
    "value": "Google"
   }
  },
  {
   "id": "x_google_attribute_mapping_email",
   "kind": "attr",
   "tier": "extra",
   "select": "google_idp",
   "cond": {
    "path": [
     "AttributeMapping",
     "email"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
