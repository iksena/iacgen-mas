package intent.cfn.row_145

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
  "spa": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "ExplicitAuthFlows",
      "*"
     ],
     "op": "in",
     "value": [
      "ALLOW_USER_SRP_AUTH",
      "USER_SRP_AUTH"
     ]
    },
    {
     "path": [
      "ExplicitAuthFlows",
      "*"
     ],
     "op": "none_eq",
     "value": "ALLOW_ADMIN_USER_PASSWORD_AUTH"
    }
   ]
  },
  "admin_client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "ExplicitAuthFlows",
      "*"
     ],
     "op": "in",
     "value": [
      "ALLOW_ADMIN_USER_PASSWORD_AUTH",
      "ADMIN_NO_SRP_AUTH"
     ]
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
  },
  "group": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": []
  },
  "rs": {
   "types": [
    "AWS::Cognito::UserPoolResourceServer"
   ],
   "where": []
  },
  "domain": {
   "types": [
    "AWS::Cognito::UserPoolDomain"
   ],
   "where": []
  },
  "env_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "allowed_values",
      "*"
     ],
     "op": "eq",
     "value": "staging"
    }
   ]
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "export"
     ],
     "op": "present"
    }
   ]
  },
  "tok_clients": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "ExplicitAuthFlows",
      "*"
     ],
     "op": "in",
     "value": [
      "ALLOW_USER_SRP_AUTH",
      "USER_SRP_AUTH",
      "ALLOW_ADMIN_USER_PASSWORD_AUTH",
      "ADMIN_NO_SRP_AUTH"
     ]
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
   "quote": "creates a Cognito user pool for AnyCompany Hotel's guest and staff authentication system"
  },
  {
   "id": "plus_tier",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "UserPoolTier"
    ],
    "op": "eq",
    "value": "PLUS"
   },
   "tier": "core",
   "quote": "using the PLUS tier"
  },
  {
   "id": "advanced_security_enforced",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "UserPoolAddOns",
     "AdvancedSecurityMode"
    ],
    "op": "eq",
    "value": "ENFORCED"
   },
   "tier": "core",
   "quote": "advanced security features enforced"
  },
  {
   "id": "email_username",
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
   "tier": "core",
   "quote": "email as the username attribute"
  },
  {
   "id": "admin_only_create",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "AdminCreateUserConfig",
     "AllowAdminCreateUserOnly"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "admin-only user creation"
  },
  {
   "id": "custom_attributes",
   "kind": "all_of",
   "tier": "detail",
   "quote": "custom attributes for guest_id, property_id, and region",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?guest_id$"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?property_id$"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?region$"
     }
    }
   ]
  },
  {
   "id": "password_policy",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "Policies",
     "PasswordPolicy"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "a solid password policy"
  },
  {
   "id": "email_recovery",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "AccountRecoverySetting",
     "RecoveryMechanisms",
     "*",
     "Name"
    ],
    "op": "eq",
    "value": "verified_email"
   },
   "tier": "detail",
   "quote": "email-based account recovery"
  },
  {
   "id": "spa_client_srp",
   "kind": "ref",
   "from": "spa",
   "to": "pool",
   "tier": "core",
   "quote": "a public SPA client using SRP auth"
  },
  {
   "id": "spa_client_no_secret",
   "kind": "attr",
   "select": "spa",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "none_eq",
    "value": true
   },
   "tier": "core",
   "quote": "with no secret"
  },
  {
   "id": "admin_auth_client",
   "kind": "ref",
   "from": "admin_client",
   "to": "pool",
   "tier": "core",
   "quote": "a separate dedicated admin auth client using ADMIN_USER_PASSWORD_AUTH"
  },
  {
   "id": "access_token_1h",
   "kind": "any_of",
   "tier": "core",
   "quote": "both with 1-hour access/id tokens",
   "justify": "1-hour = 1 (default unit hours) or 60 minutes",
   "checks": [
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
   ]
  },
  {
   "id": "id_token_1h",
   "kind": "any_of",
   "tier": "detail",
   "quote": "both with 1-hour access/id tokens",
   "justify": "1-hour = 1 (default unit hours) or 60 minutes",
   "checks": [
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
   ]
  },
  {
   "id": "refresh_token_30d",
   "kind": "any_of",
   "tier": "detail",
   "quote": "30-day refresh tokens",
   "justify": "30-day = 30 (default unit days), 720 hours or 43200 minutes",
   "checks": [
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
     }
    },
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
    },
    {
     "kind": "attr",
     "select": "tok_clients",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "RefreshTokenValidity"
        ],
        "op": "eq",
        "value": 43200
       },
       {
        "path": [
         "TokenValidityUnits",
         "RefreshToken"
        ],
        "op": "eq",
        "value": "minutes"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "staff_groups",
   "kind": "all_of",
   "tier": "core",
   "quote": "Cognito groups for Admin, Manager, RegionalManager, RevenueManager, FrontDesk, and Housekeeping staff roles",
   "checks": [
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "Admin"
     }
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "Manager"
     }
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "RegionalManager"
     }
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "RevenueManager"
     }
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "FrontDesk"
     }
    },
    {
     "kind": "attr",
     "select": "group",
     "cond": {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "Housekeeping"
     }
    }
   ]
  },
  {
   "id": "resource_server",
   "kind": "ref",
   "from": "rs",
   "to": "pool",
   "tier": "core",
   "quote": "its own resource server"
  },
  {
   "id": "resource_server_scopes",
   "kind": "all_of",
   "tier": "detail",
   "quote": "read/write/admin scopes",
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
      "value": "read"
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
      "value": "write"
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
      "value": "admin"
     }
    }
   ]
  },
  {
   "id": "m2m_client_secret",
   "kind": "attr",
   "select": "m2m",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "using client_credentials flow with a secret"
  },
  {
   "id": "m2m_client_scopes",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an M2M OAuth2 client with its own resource server and read/write/admin scopes",
   "checks": [
    {
     "kind": "attr",
     "select": "m2m",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "regex",
      "value": "/read$"
     }
    },
    {
     "kind": "attr",
     "select": "m2m",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "regex",
      "value": "/write$"
     }
    },
    {
     "kind": "attr",
     "select": "m2m",
     "cond": {
      "path": [
       "AllowedOAuthScopes",
       "*"
      ],
      "op": "regex",
      "value": "/admin$"
     }
    }
   ]
  },
  {
   "id": "user_pool_domain",
   "kind": "ref",
   "from": "domain",
   "to": "pool",
   "tier": "core",
   "quote": "a user pool domain name"
  },
  {
   "id": "domain_env_account",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a user pool domain name that includes the environment and account ID",
   "checks": [
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "Domain"
      ],
      "op": "contains",
      "value": "dev"
     }
    },
    {
     "kind": "attr",
     "select": "domain",
     "cond": {
      "path": [
       "Domain"
      ],
      "op": "contains",
      "value": "123456789012"
     }
    }
   ],
   "justify": "the account ID pseudo-parameter normalises to 123456789012; \"dev\" is the stated environment default"
  },
  {
   "id": "environment_parameter",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the environment parameter should default to dev and allow dev, staging, and prod",
   "checks": [
    {
     "kind": "attr",
     "select": "env_param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "dev"
     }
    },
    {
     "kind": "attr",
     "select": "env_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "dev"
     }
    },
    {
     "kind": "attr",
     "select": "env_param",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "prod"
     }
    }
   ]
  },
  {
   "id": "outputs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "all resources should export their IDs, ARN, client IDs, and the domain URL for cross-stack references",
   "checks": [
    {
     "kind": "ref",
     "from": "out",
     "to": "pool"
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value",
       "attr"
      ],
      "op": "eq",
      "value": "Arn"
     }
    },
    {
     "kind": "ref",
     "from": "out",
     "to": "spa"
    },
    {
     "kind": "ref",
     "from": "out",
     "to": "admin_client"
    },
    {
     "kind": "ref",
     "from": "out",
     "to": "m2m"
    }
   ]
  },
  {
   "id": "outputs_domain_url",
   "kind": "any_of",
   "tier": "detail",
   "quote": "all resources should export their IDs, ARN, client IDs, and the domain URL for cross-stack references",
   "checks": [
    {
     "kind": "ref",
     "from": "out",
     "to": "domain"
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)amazoncognito\\.com"
     }
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)domain"
     }
    }
   ],
   "justify": "the domain URL output may be a literal Cognito hosted-UI URL rather than a ref"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
