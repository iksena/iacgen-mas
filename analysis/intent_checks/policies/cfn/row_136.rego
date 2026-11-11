package intent.cfn.row_136

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
  "admin": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": [
    {
     "path": [
      "GroupName"
     ],
     "op": "eq",
     "value": "admin"
    }
   ]
  },
  "cust": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": [
    {
     "path": [
      "GroupName"
     ],
     "op": "eq",
     "value": "customer"
    }
   ]
  },
  "groups": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": []
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
  },
  "oauth_clients": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "AllowedOAuthFlows"
     ],
     "op": "present"
    }
   ]
  },
  "rs": {
   "types": [
    "AWS::Cognito::UserPoolResourceServer"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "regex",
     "value": "^/app/researchapp/agentcore/"
    }
   ]
  },
  "frole": {
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
  "pols": {
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
     "value": "cognito-idp:AdminAddUserToGroup"
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
   "quote": "creates a Cognito user pool for an application"
  },
  {
   "id": "mfa_optional",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "MfaConfiguration"
    ],
    "op": "eq",
    "value": "OPTIONAL"
   },
   "tier": "core",
   "quote": "MFA set to optional"
  },
  {
   "id": "mfa_software_token",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "EnabledMfas",
     "*"
    ],
    "op": "eq",
    "value": "SOFTWARE_TOKEN_MFA"
   },
   "tier": "core",
   "quote": "using software tokens"
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
   "quote": "email as username"
  },
  {
   "id": "email_autoverified",
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
   "quote": "auto-verified"
  },
  {
   "id": "admin_group",
   "kind": "exists",
   "select": "admin",
   "tier": "core",
   "quote": "two user groups (admin and customer)"
  },
  {
   "id": "customer_group",
   "kind": "exists",
   "select": "cust",
   "tier": "core",
   "quote": "two user groups (admin and customer)"
  },
  {
   "id": "groups_have_precedence",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "admin",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "cust",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "present"
     }
    }
   ],
   "tier": "detail",
   "quote": "the admin group has higher precedence"
  },
  {
   "id": "admin_precedence_vs_customer",
   "tier": "detail",
   "quote": "the admin group has higher precedence",
   "justify": "higher precedence means a numerically lower value",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "admin",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "lte",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "cust",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "gte",
      "value": 2
     }
    }
   ]
  },
  {
   "id": "admin_precedence_vs_customer_zero",
   "tier": "detail",
   "quote": "the admin group has higher precedence",
   "justify": "higher precedence means a numerically lower value",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "admin",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "lte",
      "value": 0
     }
    },
    {
     "kind": "attr",
     "select": "cust",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "gte",
      "value": 1
     }
    }
   ]
  },
  {
   "id": "web_client_code_flow",
   "kind": "exists",
   "select": "web",
   "tier": "core",
   "quote": "a web app client using the authorization code flow"
  },
  {
   "id": "web_client_callbacks",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "CallbackURLs",
       "*"
      ],
      "op": "eq",
      "value": "http://localhost:8501/"
     }
    },
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "CallbackURLs",
       "*"
      ],
      "op": "eq",
      "value": "https://example.com/auth/callback"
     }
    }
   ],
   "tier": "core",
   "quote": "callback URLs set to http://localhost:8501/ and https://example.com/auth/callback"
  },
  {
   "id": "m2m_client_credentials",
   "kind": "exists",
   "select": "m2m",
   "tier": "core",
   "quote": "a machine-to-machine client using client credentials flow"
  },
  {
   "id": "m2m_generated_secret",
   "kind": "attr",
   "select": "m2m",
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
   "id": "resource_server_read_scope",
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
   },
   "tier": "core",
   "quote": "a custom resource server with a read scope"
  },
  {
   "id": "clients_use_read_scope",
   "kind": "attr",
   "select": "oauth_clients",
   "cond": {
    "path": [
     "AllowedOAuthScopes",
     "*"
    ],
    "op": "regex",
    "value": "(?i)(^|/)read$"
   },
   "quantifier": "all",
   "tier": "core",
   "quote": "Both clients should use a custom resource server with a read scope"
  },
  {
   "id": "lambda_function",
   "kind": "exists",
   "select": "fn",
   "tier": "core",
   "quote": "include a Lambda function"
  },
  {
   "id": "lambda_adds_to_customer_group",
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
      "value": "(?i)admin_?add_?user_?to_?group"
     }
    },
    {
     "kind": "attr",
     "select": "frole",
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
      "value": "cognito-idp:AdminAddUserToGroup"
     }
    },
    {
     "kind": "ref",
     "from": "pols",
     "to": "frole",
     "bidirectional": true
    }
   ],
   "tier": "detail",
   "quote": "that would add new users to the customer group"
  },
  {
   "id": "lambda_not_active_trigger",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "LambdaConfig"
    ],
    "op": "absent"
   },
   "tier": "detail",
   "quote": "not wired as an active trigger"
  },
  {
   "id": "ssm_params_under_path",
   "kind": "exists",
   "select": "ssm",
   "min": 8,
   "tier": "core",
   "quote": "must be stored in SSM Parameter Store under the path /app/researchapp/agentcore/",
   "justify": "the prompt lists at least eight kinds of value (client IDs, secrets, user pool ID, scopes, discovery, token, authorize URLs, domain)"
  },
  {
   "id": "ssm_discovery_url",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "openid-configuration"
   },
   "tier": "detail",
   "quote": "discovery URL"
  },
  {
   "id": "ssm_token_url",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)oauth2/token"
   },
   "tier": "detail",
   "quote": "token URL"
  },
  {
   "id": "ssm_authorize_url",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)oauth2/authorize"
   },
   "tier": "detail",
   "quote": "authorize URL"
  },
  {
   "id": "ssm_client_secret",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "contains",
    "value": "ClientSecret"
   },
   "tier": "detail",
   "quote": "client IDs, secrets"
  },
  {
   "id": "ssm_user_pool_id",
   "tier": "detail",
   "quote": "user pool ID",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "Value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "pool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value"
        ],
        "op": "regex",
        "value": "^\\$\\{[^.}]+\\}$"
       }
      ]
     },
     "to": "pool"
    }
   ]
  },
  {
   "id": "ssm_client_ids",
   "tier": "detail",
   "quote": "client IDs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "Value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "web"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value"
        ],
        "op": "regex",
        "value": "^\\$\\{[^.}]+\\}$"
       }
      ]
     },
     "to": "web"
    }
   ]
  },
  {
   "id": "ssm_m2m_client_id",
   "tier": "detail",
   "quote": "client IDs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "Value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "m2m"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value"
        ],
        "op": "regex",
        "value": "^\\$\\{[^.}]+\\}$"
       }
      ]
     },
     "to": "m2m"
    }
   ]
  },
  {
   "id": "ssm_domain",
   "tier": "detail",
   "quote": "the Cognito domain",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "(?i)amazoncognito\\.com/?$"
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
      "value": "(?i)domain"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/researchapp/agentcore/"
       },
       {
        "path": [
         "Value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "Value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Cognito::UserPoolDomain"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "user_pool_domain",
   "tier": "detail",
   "quote": "the Cognito domain",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Cognito::UserPoolDomain"
    ],
    "where": []
   }
  },
  {
   "id": "ssm_scopes",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)(^|[/ ,])read\\b"
   },
   "tier": "detail",
   "quote": "OAuth scopes"
  },
  {
   "id": "param_user_pool_name",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "UserPoolName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "TemplateGatewayPool"
     }
    ]
   },
   "tier": "detail",
   "quote": "UserPoolName (TemplateGatewayPool)"
  },
  {
   "id": "param_machine_client_name",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "MachineAppClientName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "TemplateMachineClient"
     }
    ]
   },
   "tier": "detail",
   "quote": "MachineAppClientName (TemplateMachineClient)"
  },
  {
   "id": "param_web_client_name",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "WebAppClientName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "TemplateWebClient"
     }
    ]
   },
   "tier": "detail",
   "quote": "WebAppClientName (TemplateWebClient)"
  },
  {
   "id": "x_web_oauth_flows_enabled",
   "kind": "attr",
   "select": "web",
   "cond": {
    "path": [
     "AllowedOAuthFlowsUserPoolClient"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  },
  {
   "id": "x_web_no_secret",
   "kind": "attr",
   "select": "web",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "none_eq",
    "value": true
   },
   "tier": "extra"
  },
  {
   "id": "x_token_revocation",
   "kind": "attr",
   "select": "oauth_clients",
   "cond": {
    "path": [
     "EnableTokenRevocation"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "tier": "extra"
  },
  {
   "id": "x_lambda_python",
   "kind": "attr",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
