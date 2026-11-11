package intent.cfn.row_266

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
  "clients": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "machine": {
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
     "op": "none_eq",
     "value": "client_credentials"
    }
   ]
  },
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
  },
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "agentroles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)(bedrock|agentcore)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "tier": "core",
   "quote": "a Cognito user pool with a hosted domain",
   "select": "pool"
  },
  {
   "id": "pool_domain",
   "kind": "exists",
   "tier": "core",
   "quote": "a Cognito user pool with a hosted domain",
   "select": {
    "types": [
     "AWS::Cognito::UserPoolDomain"
    ],
    "where": []
   }
  },
  {
   "id": "domain_for_pool",
   "kind": "ref",
   "tier": "detail",
   "quote": "a Cognito user pool with a hosted domain",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolDomain"
    ],
    "where": []
   },
   "to": "pool"
  },
  {
   "id": "resource_server",
   "kind": "exists",
   "tier": "core",
   "quote": "a resource server exposing the API scopes the agent needs",
   "select": {
    "types": [
     "AWS::Cognito::UserPoolResourceServer"
    ],
    "where": []
   }
  },
  {
   "id": "scopes",
   "kind": "attr",
   "tier": "detail",
   "quote": "exposing the API scopes the agent needs",
   "select": {
    "types": [
     "AWS::Cognito::UserPoolResourceServer"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Scopes"
    ],
    "op": "len_gte",
    "value": 1
   }
  },
  {
   "id": "two_clients",
   "kind": "exists",
   "tier": "core",
   "quote": "two application clients",
   "select": "clients",
   "min": 2
  },
  {
   "id": "machine_client",
   "kind": "exists",
   "tier": "core",
   "quote": "one machine-to-machine client using the client credentials flow",
   "select": "machine"
  },
  {
   "id": "machine_scopes",
   "kind": "attr",
   "tier": "detail",
   "quote": "one machine-to-machine client using the client credentials flow",
   "justify": "client credentials flow needs custom scopes from the resource server",
   "select": "machine",
   "cond": {
    "path": [
     "AllowedOAuthScopes"
    ],
    "op": "present"
   }
  },
  {
   "id": "web_client",
   "kind": "exists",
   "tier": "core",
   "quote": "one web client for interactive sign-in",
   "select": "web"
  },
  {
   "id": "web_public",
   "tier": "extra",
   "kind": "attr",
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
   "id": "web_interactive",
   "kind": "any_of",
   "tier": "detail",
   "quote": "one web client for interactive sign-in",
   "justify": "interactive sign-in is an authorization code or implicit flow or a user auth flow; omitted ExplicitAuthFlows already allows SRP",
   "checks": [
    {
     "kind": "attr",
     "select": "web",
     "cond": {
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
      "value": "(?i)(USER_SRP|USER_PASSWORD|USER_AUTH|CUSTOM_AUTH)"
     }
    },
    {
     "kind": "attr",
     "select": "web",
     "cond": {
      "path": [
       "ExplicitAuthFlows"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "test_user_email_param",
   "tier": "detail",
   "quote": "a seeded test user whose email and password come from parameters with placeholder defaults",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "@"
     }
    },
    {
     "kind": "attr",
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
        "value": "(?i)e-?mail"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "test_user_password_param",
   "tier": "detail",
   "quote": "a seeded test user whose email and password come from parameters with placeholder defaults",
   "kind": "attr",
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
      "value": "(?i)(pass|pwd)"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "present"
   }
  },
  {
   "id": "finance_table",
   "kind": "exists",
   "tier": "core",
   "quote": "a DynamoDB table to hold the finance tracking state",
   "select": "table"
  },
  {
   "id": "two_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "two IAM execution roles",
   "select": "roles",
   "min": 2
  },
  {
   "id": "agentcore_roles",
   "kind": "exists",
   "tier": "detail",
   "quote": "one for the MCP server runtime and one for the agent runtime",
   "justify": "roles for Amazon Bedrock AgentCore runtimes are assumed by a bedrock service principal",
   "select": "agentroles",
   "min": 2
  },
  {
   "id": "ssm_params",
   "kind": "exists",
   "tier": "core",
   "quote": "publish the values the runtimes need to discover each other",
   "justify": "the prompt lists nine values: pool id and ARN, two client ids, two endpoints, table name, two role ARNs",
   "select": "ssm",
   "min": 9
  },
  {
   "id": "ssm_paths",
   "kind": "attr",
   "tier": "detail",
   "quote": "under a path derived from a project name parameter",
   "select": {
    "types": [
     "AWS::SSM::Parameter"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^/[^/]+/"
   },
   "quantifier": "all"
  },
  {
   "id": "project_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "a path derived from a project name parameter",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)project"
   }
  },
  {
   "id": "ssm_pool",
   "tier": "detail",
   "quote": "the user pool identifier and ARN",
   "kind": "ref",
   "to": "pool",
   "from": {
    "types": [
     "AWS::SSM::Parameter"
    ],
    "where": [
     {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "^(\\{|\\$\\{)"
     },
     {
      "path": [
       "Value",
       "attr"
      ],
      "op": "none_eq",
      "value": "Arn"
     }
    ]
   }
  },
  {
   "id": "ssm_pool_arn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the user pool identifier and ARN",
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
         "Value",
         "attr"
        ],
        "op": "eq",
        "value": "Arn"
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
         "Value"
        ],
        "op": "regex",
        "value": "(?i)(\\.Arn\\}|userpool/)"
       }
      ]
     },
     "to": "pool"
    }
   ]
  },
  {
   "id": "ssm_machine_client",
   "kind": "ref",
   "tier": "detail",
   "quote": "both client identifiers",
   "from": "ssm",
   "to": "machine"
  },
  {
   "id": "ssm_web_client",
   "kind": "ref",
   "tier": "detail",
   "quote": "both client identifiers",
   "from": "ssm",
   "to": "web"
  },
  {
   "id": "ssm_discovery",
   "tier": "detail",
   "quote": "the OpenID discovery and token endpoints",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)openid-configuration"
   }
  },
  {
   "id": "ssm_token",
   "tier": "detail",
   "quote": "the OpenID discovery and token endpoints",
   "kind": "attr",
   "select": "ssm",
   "cond": {
    "path": [
     "Value"
    ],
    "op": "regex",
    "value": "(?i)oauth2/token"
   }
  },
  {
   "id": "ssm_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the table name",
   "checks": [
    {
     "kind": "ref",
     "from": "ssm",
     "to": "table"
    },
    {
     "kind": "join",
     "from": "ssm",
     "from_path": [
      "Value"
     ],
     "to": "table",
     "to_path": [
      "TableName"
     ]
    }
   ]
  },
  {
   "id": "ssm_roles",
   "tier": "detail",
   "quote": "both role ARNs",
   "justify": "two role ARNs: SSM parameters whose name says role, or the pool ARN plus two role ARN references",
   "kind": "any_of",
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
        "value": "(?i)role"
       },
       {
        "path": [
         "Value"
        ],
        "op": "regex",
        "value": "(?i)(\"ref\"|arn:|\\$\\{)"
       }
      ]
     },
     "min": 2
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
         "Value",
         "attr"
        ],
        "op": "eq",
        "value": "Arn"
       }
      ]
     },
     "min": 3
    }
   ]
  },
  {
   "id": "x_machine_secret",
   "kind": "attr",
   "tier": "extra",
   "select": "machine",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_auto_verify",
   "kind": "attr",
   "tier": "extra",
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
   "id": "x_table_on_demand",
   "kind": "attr",
   "tier": "extra",
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
   "id": "x_table_range_key",
   "kind": "attr",
   "tier": "extra",
   "select": "table",
   "cond": {
    "path": [
     "KeySchema"
    ],
    "op": "len_eq",
    "value": 2
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
