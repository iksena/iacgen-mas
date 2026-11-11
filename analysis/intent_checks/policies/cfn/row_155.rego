package intent.cfn.row_155

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
  "groups": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
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
  "clients": {
   "types": [
    "AWS::Cognito::UserPoolClient"
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
     "value": "^/app/customersupport/agentcore/"
    }
   ]
  },
  "ssm_disc": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "regex",
     "value": "^/app/customersupport/agentcore/"
    },
    {
     "path": [
      "Value"
     ],
     "op": "contains",
     "value": "openid-configuration"
    }
   ]
  },
  "ssm_token": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "regex",
     "value": "^/app/customersupport/agentcore/"
    },
    {
     "path": [
      "Value"
     ],
     "op": "contains",
     "value": "oauth2/token"
    }
   ]
  },
  "ssm_auth": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "regex",
     "value": "^/app/customersupport/agentcore/"
    },
    {
     "path": [
      "Value"
     ],
     "op": "contains",
     "value": "oauth2/authorize"
    }
   ]
  },
  "ssm_scope": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "regex",
     "value": "^/app/customersupport/agentcore/"
    },
    {
     "path": [
      "Value"
     ],
     "op": "regex",
     "value": "(^|/)read$"
    }
   ]
  },
  "roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "tier": "core",
   "quote": "a user pool",
   "select": "pool"
  },
  {
   "id": "email_username",
   "kind": "attr",
   "tier": "core",
   "quote": "email as the username",
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
   "id": "auto_verify",
   "kind": "attr",
   "tier": "core",
   "quote": "auto-verification",
   "justify": "auto-verification of the email username means email is auto-verified",
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
   "id": "group_admin",
   "kind": "attr",
   "tier": "core",
   "quote": "two user groups named \"admin\" and \"customer\"",
   "select": "groups",
   "cond": {
    "path": [
     "GroupName"
    ],
    "op": "eq",
    "value": "admin"
   }
  },
  {
   "id": "group_customer",
   "kind": "attr",
   "tier": "core",
   "quote": "two user groups named \"admin\" and \"customer\"",
   "select": "groups",
   "cond": {
    "path": [
     "GroupName"
    ],
    "op": "eq",
    "value": "customer"
   }
  },
  {
   "id": "admin_precedence",
   "kind": "attr",
   "tier": "detail",
   "quote": "where admin has higher precedence",
   "select": "admin",
   "cond": {
    "path": [
     "Precedence"
    ],
    "op": "present"
   }
  },
  {
   "id": "customer_precedence",
   "kind": "attr",
   "tier": "detail",
   "quote": "where admin has higher precedence",
   "select": "cust",
   "cond": {
    "path": [
     "Precedence"
    ],
    "op": "present"
   }
  },
  {
   "id": "precedence_order_1",
   "tier": "detail",
   "kind": "any_of",
   "quote": "where admin has higher precedence",
   "justify": "in Cognito a lower Precedence value wins; two resources cannot be compared directly, so this rejects admin above and customer at or below this value",
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
   "id": "precedence_order_5",
   "tier": "detail",
   "kind": "any_of",
   "quote": "where admin has higher precedence",
   "justify": "in Cognito a lower Precedence value wins; two resources cannot be compared directly, so this rejects admin above and customer at or below this value",
   "checks": [
    {
     "kind": "attr",
     "select": "admin",
     "cond": {
      "path": [
       "Precedence"
      ],
      "op": "lte",
      "value": 5
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
      "value": 6
     }
    }
   ]
  },
  {
   "id": "groups_in_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "two user groups named \"admin\" and \"customer\"",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolGroup"
    ],
    "where": []
   },
   "to": "pool"
  },
  {
   "id": "web_client",
   "kind": "exists",
   "tier": "core",
   "quote": "a web application client using authorization code grant flow",
   "select": "web"
  },
  {
   "id": "web_scope",
   "kind": "attr",
   "tier": "core",
   "quote": "with a custom read scope",
   "select": "web",
   "cond": {
    "path": [
     "AllowedOAuthScopes",
     "*"
    ],
    "op": "regex",
    "value": "(^|/)read$"
   }
  },
  {
   "id": "web_callback",
   "kind": "attr",
   "tier": "detail",
   "quote": "callback/logout URLs",
   "select": "web",
   "cond": {
    "path": [
     "CallbackURLs"
    ],
    "op": "present"
   }
  },
  {
   "id": "web_logout",
   "kind": "attr",
   "tier": "detail",
   "quote": "callback/logout URLs",
   "select": "web",
   "cond": {
    "path": [
     "LogoutURLs"
    ],
    "op": "present"
   }
  },
  {
   "id": "m2m_client",
   "kind": "exists",
   "tier": "core",
   "quote": "a machine-to-machine client using client credentials grant",
   "select": "m2m"
  },
  {
   "id": "m2m_scope",
   "kind": "attr",
   "tier": "core",
   "quote": "with the same read scope",
   "select": "m2m",
   "cond": {
    "path": [
     "AllowedOAuthScopes",
     "*"
    ],
    "op": "regex",
    "value": "(^|/)read$"
   }
  },
  {
   "id": "two_clients",
   "kind": "exists",
   "tier": "core",
   "quote": "a web application client using authorization code grant flow with a custom read scope and callback/logout URLs, a machine-to-machine client",
   "justify": "a web client and a machine-to-machine client are two clients",
   "select": "clients",
   "min": 2
  },
  {
   "id": "clients_in_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "a web application client",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolClient"
    ],
    "where": []
   },
   "to": "pool"
  },
  {
   "id": "resource_server",
   "kind": "exists",
   "tier": "core",
   "quote": "a resource server defining that scope",
   "select": "rs"
  },
  {
   "id": "rs_scope",
   "kind": "attr",
   "tier": "core",
   "quote": "a resource server defining that scope",
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
   "id": "domain",
   "kind": "exists",
   "tier": "core",
   "quote": "a Cognito domain for the hosted UI",
   "select": "domain"
  },
  {
   "id": "domain_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "a Cognito domain for the hosted UI",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolDomain"
    ],
    "where": []
   },
   "to": "pool"
  },
  {
   "id": "lambda",
   "kind": "exists",
   "tier": "core",
   "quote": "a Lambda function that automatically adds new sign-ups to the customer group",
   "select": "fn"
  },
  {
   "id": "lambda_adds_to_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "a Lambda function that automatically adds new sign-ups to the customer group",
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
      "value": "(?i)admin_?add_?user_?to_?group"
     }
    },
    {
     "kind": "ref",
     "from": "fn",
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
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
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
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
     },
     "to": "roles"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
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
     },
     "to": "roles",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "lambda_customer_group",
   "tier": "detail",
   "kind": "any_of",
   "quote": "adds new sign-ups to the customer group",
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
      "value": "(?i)customer"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Environment"
      ],
      "op": "regex",
      "value": "(?i)customer"
     }
    }
   ]
  },
  {
   "id": "ssm_params",
   "kind": "exists",
   "tier": "core",
   "quote": "SSM parameters storing the client IDs, user pool ID, OAuth scope, discovery URL, token endpoint, authorize endpoint, and domain under the path /app/customersupport/agentcore/",
   "justify": "two client IDs, user pool ID, scope, discovery URL, token endpoint, authorize endpoint and domain make eight parameters",
   "select": "ssm",
   "min": 8
  },
  {
   "id": "ssm_web_client",
   "kind": "ref",
   "tier": "detail",
   "quote": "SSM parameters storing the client IDs",
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
      "value": "^/app/customersupport/agentcore/"
     }
    ]
   },
   "to": "web"
  },
  {
   "id": "ssm_m2m_client",
   "kind": "ref",
   "tier": "detail",
   "quote": "SSM parameters storing the client IDs",
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
      "value": "^/app/customersupport/agentcore/"
     }
    ]
   },
   "to": "m2m"
  },
  {
   "id": "ssm_pool_id",
   "kind": "ref",
   "tier": "detail",
   "quote": "user pool ID",
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
      "value": "^/app/customersupport/agentcore/"
     },
     {
      "path": [
       "Value",
       "ref"
      ],
      "op": "present"
     }
    ]
   },
   "to": "pool"
  },
  {
   "id": "ssm_scope",
   "kind": "exists",
   "tier": "detail",
   "quote": "OAuth scope",
   "select": "ssm_scope"
  },
  {
   "id": "ssm_discovery",
   "kind": "exists",
   "tier": "detail",
   "quote": "discovery URL",
   "justify": "a Cognito OIDC discovery URL is the openid-configuration document",
   "select": "ssm_disc"
  },
  {
   "id": "ssm_token",
   "kind": "exists",
   "tier": "detail",
   "quote": "token endpoint",
   "select": "ssm_token"
  },
  {
   "id": "ssm_authorize",
   "kind": "exists",
   "tier": "detail",
   "quote": "authorize endpoint",
   "select": "ssm_auth"
  },
  {
   "id": "ssm_domain",
   "tier": "detail",
   "kind": "any_of",
   "quote": "and domain under the path /app/customersupport/agentcore/",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "^/app/customersupport/agentcore/"
       },
       {
        "path": [
         "Value"
        ],
        "op": "regex",
        "value": "amazoncognito\\.com/?$"
       }
      ]
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
        "value": "^/app/customersupport/agentcore/"
       }
      ]
     },
     "to": "domain"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "(?i)^/app/customersupport/agentcore/.*domain"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_oauth_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "clients",
   "cond": {
    "path": [
     "AllowedOAuthFlowsUserPoolClient"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "x_m2m_secret",
   "kind": "attr",
   "tier": "extra",
   "select": "m2m",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_web_nosecret",
   "kind": "attr",
   "tier": "extra",
   "select": "web",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "x_revocation",
   "kind": "attr",
   "tier": "extra",
   "select": "clients",
   "cond": {
    "path": [
     "EnableTokenRevocation"
    ],
    "op": "none_eq",
    "value": false
   },
   "quantifier": "all"
  },
  {
   "id": "x_idp",
   "kind": "attr",
   "tier": "extra",
   "select": "clients",
   "cond": {
    "path": [
     "SupportedIdentityProviders",
     "*"
    ],
    "op": "eq",
    "value": "COGNITO"
   },
   "quantifier": "all"
  },
  {
   "id": "x_runtime",
   "kind": "attr",
   "tier": "extra",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python3"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
