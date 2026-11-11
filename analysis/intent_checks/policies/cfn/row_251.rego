package intent.cfn.row_251

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ppool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": [
    {
     "path": [
      "UserPoolName"
     ],
     "op": "eq",
     "value": "PooledTenant-SaaSOperationsUserPool"
    }
   ]
  },
  "opool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": [
    {
     "path": [
      "UserPoolName"
     ],
     "op": "eq",
     "value": "OperationUsers-SaaSOperationsUserPool"
    }
   ]
  },
  "pclient": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "ClientName"
     ],
     "op": "eq",
     "value": "SaaSOperationsClient"
    }
   ]
  },
  "oclient": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": [
    {
     "path": [
      "ClientName"
     ],
     "op": "eq",
     "value": "SaaSOperationsOperationUsersPoolClient"
    }
   ]
  },
  "pdomain": {
   "types": [
    "AWS::Cognito::UserPoolDomain"
   ],
   "where": [
    {
     "path": [
      "Domain"
     ],
     "op": "regex",
     "value": "^pooledtenant-saasoperations-.+"
    }
   ]
  },
  "odomain": {
   "types": [
    "AWS::Cognito::UserPoolDomain"
   ],
   "where": [
    {
     "path": [
      "Domain"
     ],
     "op": "regex",
     "value": "^operationsusers-saasoperations-.+"
    }
   ]
  },
  "pidp": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": [
    {
     "path": [
      "IdentityPoolName"
     ],
     "op": "eq",
     "value": "PooledTenant-SaaSOperationsIdentityPool"
    }
   ]
  },
  "oidp": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": [
    {
     "path": [
      "IdentityPoolName"
     ],
     "op": "eq",
     "value": "OperationsUser-SaaSOperationsIdentityPool"
    }
   ]
  },
  "prole": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "eq",
     "value": "authenticated-pooled-user-role"
    }
   ]
  },
  "srole": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "eq",
     "value": "authenticated-siloed-user-role"
    }
   ]
  },
  "ptag": {
   "types": [
    "AWS::Cognito::IdentityPoolPrincipalTag"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": []
  },
  "idp": {
   "types": [
    "AWS::Cognito::UserPoolIdentityProvider"
   ],
   "where": []
  },
  "group": {
   "types": [
    "AWS::Cognito::UserPoolGroup"
   ],
   "where": []
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "req_params",
   "kind": "exists",
   "tier": "detail",
   "quote": "two required string parameters for the tenant application callback host and the admin application callback host",
   "justify": "two required string parameters means two parameters of type String with no default",
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
      "value": "String"
     },
     {
      "path": [
       "default"
      ],
      "op": "absent"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "siloed_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "a siloed tenant role name parameter defaulting to \"authenticated-siloed-user-role\"",
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
    "op": "eq",
    "value": "authenticated-siloed-user-role"
   }
  },
  {
   "id": "ppool",
   "kind": "exists",
   "tier": "core",
   "quote": "a pooled tenant user pool named \"PooledTenant-SaaSOperationsUserPool\"",
   "select": "ppool"
  },
  {
   "id": "ppool_verify",
   "kind": "attr",
   "tier": "core",
   "quote": "auto-verified email",
   "select": "ppool",
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
   "id": "ppool_recovery",
   "kind": "attr",
   "tier": "core",
   "quote": "email-based account recovery",
   "justify": "email recovery is the verified_email mechanism",
   "select": "ppool",
   "cond": {
    "path": [
     "AccountRecoverySetting"
    ],
    "op": "regex",
    "value": "(?i)verified_email"
   }
  },
  {
   "id": "ppool_email_req",
   "kind": "attr",
   "tier": "detail",
   "quote": "a required email attribute",
   "select": "ppool",
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
      "op": "eq",
      "value": "true"
     }
    ]
   },
   "justify": "a required attribute has Required true"
  },
  {
   "id": "ppool_custom",
   "kind": "all_of",
   "tier": "detail",
   "quote": "custom tenantId and userRole attributes",
   "checks": [
    {
     "kind": "attr",
     "select": "ppool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?tenantId$"
     }
    },
    {
     "kind": "attr",
     "select": "ppool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?userRole$"
     }
    }
   ]
  },
  {
   "id": "ppool_invite",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an invitation email that points users to the tenant application URL with their temporary password",
   "justify": "Cognito's temporary password placeholder is {####}; an application URL is an http(s) URL",
   "checks": [
    {
     "kind": "attr",
     "select": "ppool",
     "cond": {
      "path": [
       "AdminCreateUserConfig",
       "InviteMessageTemplate",
       "EmailMessage"
      ],
      "op": "regex",
      "value": "https?://"
     }
    },
    {
     "kind": "attr",
     "select": "ppool",
     "cond": {
      "path": [
       "AdminCreateUserConfig",
       "InviteMessageTemplate",
       "EmailMessage"
      ],
      "op": "contains",
      "value": "{####}"
     }
    }
   ]
  },
  {
   "id": "pclient",
   "kind": "exists",
   "tier": "core",
   "quote": "a public app client named \"SaaSOperationsClient\"",
   "select": "pclient"
  },
  {
   "id": "pclient_nosecret",
   "kind": "any_of",
   "tier": "core",
   "quote": "without a secret",
   "checks": [
    {
     "kind": "attr",
     "select": "pclient",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "eq",
      "value": "false"
     }
    },
    {
     "kind": "attr",
     "select": "pclient",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "without a secret means GenerateSecret false"
  },
  {
   "id": "pclient_flows",
   "kind": "all_of",
   "tier": "core",
   "quote": "supports the authorization code and implicit flows",
   "checks": [
    {
     "kind": "attr",
     "select": "pclient",
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
     "select": "pclient",
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
   "id": "pclient_scopes",
   "kind": "all_of",
   "tier": "core",
   "quote": "with email, openid, and profile scopes",
   "checks": [
    {
     "kind": "attr",
     "select": "pclient",
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
     "select": "pclient",
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
     "select": "pclient",
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
   "id": "pclient_urls",
   "kind": "all_of",
   "tier": "detail",
   "quote": "uses the tenant application URL for callback and logout",
   "checks": [
    {
     "kind": "attr",
     "select": "pclient",
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
     "select": "pclient",
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
   "justify": "an application URL is an https URL"
  },
  {
   "id": "pclient_write",
   "kind": "all_of",
   "tier": "detail",
   "quote": "can write the email, tenantId, and userRole attributes",
   "checks": [
    {
     "kind": "attr",
     "select": "pclient",
     "cond": {
      "path": [
       "WriteAttributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    },
    {
     "kind": "attr",
     "select": "pclient",
     "cond": {
      "path": [
       "WriteAttributes",
       "*"
      ],
      "op": "regex",
      "value": "^(custom:)?tenantId$"
     }
    },
    {
     "kind": "attr",
     "select": "pclient",
     "cond": {
      "path": [
       "WriteAttributes",
       "*"
      ],
      "op": "regex",
      "value": "^(custom:)?userRole$"
     }
    }
   ]
  },
  {
   "id": "pclient_idtoken",
   "kind": "any_of",
   "tier": "core",
   "quote": "issues ID tokens valid for 12 hours",
   "justify": "12 hours = 12 in the default hours unit, 720 minutes or 43200 seconds",
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
         "ClientName"
        ],
        "op": "eq",
        "value": "SaaSOperationsClient"
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
     "cond": {
      "path": [
       "IdTokenValidity"
      ],
      "op": "eq",
      "value": 12
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
         "ClientName"
        ],
        "op": "eq",
        "value": "SaaSOperationsClient"
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
     "cond": {
      "path": [
       "IdTokenValidity"
      ],
      "op": "eq",
      "value": 12
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
         "ClientName"
        ],
        "op": "eq",
        "value": "SaaSOperationsClient"
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
     "cond": {
      "path": [
       "IdTokenValidity"
      ],
      "op": "eq",
      "value": 720
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
         "ClientName"
        ],
        "op": "eq",
        "value": "SaaSOperationsClient"
       },
       {
        "path": [
         "TokenValidityUnits",
         "IdToken"
        ],
        "op": "eq",
        "value": "seconds"
       }
      ]
     },
     "cond": {
      "path": [
       "IdTokenValidity"
      ],
      "op": "eq",
      "value": 43200
     }
    }
   ]
  },
  {
   "id": "pdomain",
   "kind": "attr",
   "tier": "core",
   "quote": "a hosted domain named \"pooledtenant-saasoperations\" suffixed with the account ID",
   "justify": "suffixed with the account ID: the adapter resolves AWS::AccountId to 123456789012",
   "select": "pdomain",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "regex",
    "value": "^pooledtenant-saasoperations-?123456789012$"
   }
  },
  {
   "id": "pidp",
   "kind": "exists",
   "tier": "core",
   "quote": "an identity pool named \"PooledTenant-SaaSOperationsIdentityPool\"",
   "select": "pidp"
  },
  {
   "id": "pidp_unauth",
   "kind": "attr",
   "tier": "core",
   "quote": "disallows unauthenticated identities",
   "select": "pidp",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": "false"
   },
   "justify": "disallowing means AllowUnauthenticatedIdentities false"
  },
  {
   "id": "ptag",
   "kind": "ref",
   "tier": "core",
   "quote": "maps the tenantId and userRole custom attributes to session principal tags",
   "from": {
    "types": [
     "AWS::Cognito::IdentityPoolPrincipalTag"
    ],
    "where": [
     {
      "path": [
       "PrincipalTags",
       "*"
      ],
      "op": "eq",
      "value": "custom:tenantId"
     },
     {
      "path": [
       "PrincipalTags",
       "*"
      ],
      "op": "eq",
      "value": "custom:userRole"
     }
    ]
   },
   "to": "pidp"
  },
  {
   "id": "prole",
   "kind": "exists",
   "tier": "core",
   "quote": "an authenticated IAM role named \"authenticated-pooled-user-role\"",
   "select": "prole"
  },
  {
   "id": "prole_assume",
   "kind": "all_of",
   "tier": "core",
   "quote": "that federated identities can assume and tag sessions with",
   "justify": "federated identities assume via sts:AssumeRoleWithWebIdentity and tag sessions via sts:TagSession",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
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
        "value": "allow"
       },
       {
        "path": [
         "Principal",
         "Federated",
         "*"
        ],
        "op": "eq",
        "value": "cognito-identity.amazonaws.com"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sts:AssumeRoleWithWebIdentity"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
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
        "value": "allow"
       },
       {
        "path": [
         "Principal",
         "Federated",
         "*"
        ],
        "op": "eq",
        "value": "cognito-identity.amazonaws.com"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sts:TagSession"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_attached",
   "kind": "ref",
   "tier": "core",
   "quote": "attaches an authenticated IAM role",
   "from": "attach",
   "to": "prole"
  },
  {
   "id": "prole_product",
   "kind": "any_of",
   "tier": "core",
   "quote": "tenant-prefixed item access on the pooled Product and Order tables",
   "justify": "item access is dynamodb item actions; tenant-prefixed means a tenantId principal-tag condition; the Product/Order table names are not given, so any table name containing the word",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*product"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)PrincipalTag/tenantId"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*product"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)PrincipalTag/tenantId"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_order",
   "kind": "any_of",
   "tier": "core",
   "quote": "tenant-prefixed item access on the pooled Product and Order tables",
   "justify": "item access is dynamodb item actions; tenant-prefixed means a tenantId principal-tag condition; the Product/Order table names are not given, so any table name containing the word",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*order"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)PrincipalTag/tenantId"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*order"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)PrincipalTag/tenantId"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_admin_tum",
   "kind": "any_of",
   "tier": "detail",
   "quote": "TenantAdmin access to the tenant user mapping, tenant details, tenant stack mapping, and settings tables",
   "justify": "tenant user mapping table named in the prompt; TenantAdmin role condition",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?user[-_]?mapping"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?user[-_]?mapping"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_admin_td",
   "kind": "any_of",
   "tier": "detail",
   "quote": "TenantAdmin access to the tenant user mapping, tenant details, tenant stack mapping, and settings tables",
   "justify": "tenant details table named in the prompt; TenantAdmin role condition",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?details"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?details"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_admin_tsm",
   "kind": "any_of",
   "tier": "detail",
   "quote": "TenantAdmin access to the tenant user mapping, tenant details, tenant stack mapping, and settings tables",
   "justify": "tenant stack mapping table named in the prompt; TenantAdmin role condition",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?stack[-_]?mapping"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*tenant[-_]?stack[-_]?mapping"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_admin_set",
   "kind": "any_of",
   "tier": "detail",
   "quote": "TenantAdmin access to the tenant user mapping, tenant details, tenant stack mapping, and settings tables",
   "justify": "settings tables table named in the prompt; TenantAdmin role condition",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*settings"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/.*settings"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "TenantAdmin"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prole_sysadmin",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SystemAdmin access to all tables and indexes",
   "justify": "all tables and indexes = a table/* (or *) resource; IAM wildcards also match table/X/index/Y",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(table/\\*$|^\\*$)"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "SystemAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(table/\\*$|^\\*$)"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "SystemAdmin"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "srole",
   "kind": "exists",
   "tier": "core",
   "quote": "the siloed tenant role",
   "justify": "its name is the stated parameter default",
   "select": "srole"
  },
  {
   "id": "srole_product",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Product and Order table names are suffixed with the caller's tenant ID",
   "justify": "suffix is the caller's tenantId principal tag",
   "checks": [
    {
     "kind": "attr",
     "select": "srole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*product[^/]*principaltag/tenantid\\}"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*product[^/]*principaltag/tenantid\\}"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "srole_order",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Product and Order table names are suffixed with the caller's tenant ID",
   "justify": "suffix is the caller's tenantId principal tag",
   "checks": [
    {
     "kind": "attr",
     "select": "srole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*order[^/]*principaltag/tenantid\\}"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "(?i)table/[^/]*order[^/]*principaltag/tenantid\\}"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "opool",
   "kind": "exists",
   "tier": "core",
   "quote": "an operations users pool named \"OperationUsers-SaaSOperationsUserPool\"",
   "select": "opool"
  },
  {
   "id": "opool_verify",
   "kind": "attr",
   "tier": "detail",
   "quote": "the same email and custom attribute setup",
   "select": "opool",
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
   "id": "opool_custom",
   "kind": "all_of",
   "tier": "detail",
   "quote": "plus a custom apiKey attribute",
   "checks": [
    {
     "kind": "attr",
     "select": "opool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?tenantId$"
     }
    },
    {
     "kind": "attr",
     "select": "opool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?userRole$"
     }
    },
    {
     "kind": "attr",
     "select": "opool",
     "cond": {
      "path": [
       "Schema",
       "*",
       "Name"
      ],
      "op": "regex",
      "value": "^(custom:)?apiKey$"
     }
    }
   ]
  },
  {
   "id": "opool_invite",
   "kind": "attr",
   "tier": "detail",
   "quote": "an invitation email pointing to the admin application URL",
   "select": "opool",
   "cond": {
    "path": [
     "AdminCreateUserConfig",
     "InviteMessageTemplate",
     "EmailMessage"
    ],
    "op": "regex",
    "value": "https?://"
   },
   "justify": "an application URL is an http(s) URL"
  },
  {
   "id": "oclient",
   "kind": "exists",
   "tier": "core",
   "quote": "a secret-less app client named \"SaaSOperationsOperationUsersPoolClient\"",
   "select": "oclient"
  },
  {
   "id": "oclient_nosecret",
   "kind": "any_of",
   "tier": "core",
   "quote": "secret-less app client",
   "checks": [
    {
     "kind": "attr",
     "select": "oclient",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "eq",
      "value": "false"
     }
    },
    {
     "kind": "attr",
     "select": "oclient",
     "cond": {
      "path": [
       "GenerateSecret"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "secret-less means GenerateSecret false"
  },
  {
   "id": "oclient_urls",
   "kind": "attr",
   "tier": "detail",
   "quote": "using the admin URL for callbacks",
   "select": "oclient",
   "cond": {
    "path": [
     "CallbackURLs",
     "*"
    ],
    "op": "regex",
    "value": "^https?://"
   },
   "justify": "an application URL is an https URL"
  },
  {
   "id": "odomain",
   "kind": "attr",
   "tier": "core",
   "quote": "a hosted domain named \"operationsusers-saasoperations\" suffixed with the account ID",
   "justify": "suffixed with the account ID: the adapter resolves AWS::AccountId to 123456789012",
   "select": "odomain",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "regex",
    "value": "^operationsusers-saasoperations-?123456789012$"
   }
  },
  {
   "id": "group",
   "kind": "ref",
   "tier": "core",
   "quote": "a \"SystemAdmins\" user group",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolGroup"
    ],
    "where": [
     {
      "path": [
       "GroupName"
      ],
      "op": "eq",
      "value": "SystemAdmins"
     }
    ]
   },
   "to": "opool"
  },
  {
   "id": "group_prec",
   "kind": "attr",
   "tier": "core",
   "quote": "with precedence 0",
   "select": "group",
   "cond": {
    "path": [
     "Precedence"
    ],
    "op": "eq",
    "value": 0
   }
  },
  {
   "id": "oidp",
   "kind": "exists",
   "tier": "core",
   "quote": "an identity pool named \"OperationsUser-SaaSOperationsIdentityPool\"",
   "select": "oidp"
  },
  {
   "id": "oidp_tag",
   "kind": "ref",
   "tier": "core",
   "quote": "with the same principal tag mapping",
   "from": {
    "types": [
     "AWS::Cognito::IdentityPoolPrincipalTag"
    ],
    "where": [
     {
      "path": [
       "PrincipalTags",
       "*"
      ],
      "op": "eq",
      "value": "custom:tenantId"
     },
     {
      "path": [
       "PrincipalTags",
       "*"
      ],
      "op": "eq",
      "value": "custom:userRole"
     }
    ]
   },
   "to": "oidp"
  },
  {
   "id": "oidp_role",
   "kind": "ref",
   "tier": "core",
   "quote": "also uses the pooled user role for authenticated identities",
   "from": "attach",
   "to": "oidp"
  },
  {
   "id": "oidp_pooled_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "uses the pooled user role for authenticated identities",
   "from": "attach",
   "to": "prole"
  },
  {
   "id": "idp_two",
   "kind": "exists",
   "tier": "core",
   "quote": "Register each user pool as an OIDC identity provider named \"Cognito\"",
   "justify": "each of the two user pools gets a provider",
   "select": {
    "types": [
     "AWS::Cognito::UserPoolIdentityProvider"
    ],
    "where": [
     {
      "path": [
       "ProviderName"
      ],
      "op": "eq",
      "value": "Cognito"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "idp_oidc",
   "kind": "attr",
   "tier": "detail",
   "quote": "as an OIDC identity provider",
   "select": "idp",
   "quantifier": "all",
   "cond": {
    "path": [
     "ProviderType"
    ],
    "op": "eq",
    "value": "OIDC"
   }
  },
  {
   "id": "idp_pools",
   "kind": "all_of",
   "tier": "detail",
   "quote": "pointing at its own issuer and client",
   "checks": [
    {
     "kind": "ref",
     "from": "idp",
     "to": "ppool"
    },
    {
     "kind": "ref",
     "from": "idp",
     "to": "opool"
    },
    {
     "kind": "ref",
     "from": "idp",
     "to": "pclient"
    },
    {
     "kind": "ref",
     "from": "idp",
     "to": "oclient"
    }
   ]
  },
  {
   "id": "outs_count",
   "kind": "exists",
   "tier": "detail",
   "quote": "output the user pool, identity pool, and client IDs, the siloed role name and ARN, and the operations user pool provider URL",
   "justify": "pool, identity pool, client, role name, role ARN, provider URL",
   "select": "outs",
   "min": 6
  },
  {
   "id": "outs_refs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "output the user pool, identity pool, and client IDs",
   "checks": [
    {
     "kind": "ref",
     "from": "outs",
     "to": "ppool"
    },
    {
     "kind": "ref",
     "from": "outs",
     "to": "pidp"
    },
    {
     "kind": "ref",
     "from": "outs",
     "to": "pclient"
    }
   ]
  },
  {
   "id": "out_srole",
   "kind": "ref",
   "tier": "detail",
   "quote": "the siloed role name and ARN",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "eq",
      "value": "Arn"
     }
    ]
   },
   "to": "srole"
  },
  {
   "id": "out_srole_name",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the siloed role name",
   "checks": [
    {
     "kind": "attr",
     "select": "outs",
     "cond": {
      "path": [
       "value"
      ],
      "op": "eq",
      "value": "authenticated-siloed-user-role"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "srole"
    }
   ]
  },
  {
   "id": "out_provider",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the operations user pool provider URL",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "ProviderURL"
       }
      ]
     },
     "to": "opool"
    },
    {
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
        "value": "cognito-idp\\.[^ ]*amazonaws\\.com/"
       }
      ]
     },
     "to": "opool"
    }
   ],
   "justify": "a user pool provider URL is GetAtt ProviderURL or https://cognito-idp.<region>.amazonaws.com/<pool id>"
  },
  {
   "id": "x_pidp_provider",
   "kind": "ref",
   "tier": "extra",
   "from": "pidp",
   "to": "ppool"
  },
  {
   "id": "x_ptag_defaults",
   "kind": "attr",
   "tier": "extra",
   "select": "ptag",
   "cond": {
    "path": [
     "UseDefaults"
    ],
    "op": "eq",
    "value": "false"
   }
  },
  {
   "id": "x_servercheck",
   "kind": "attr",
   "tier": "extra",
   "select": "pidp",
   "cond": {
    "path": [
     "CognitoIdentityProviders",
     "*",
     "ServerSideTokenCheck"
    ],
    "op": "eq",
    "value": "true"
   }
  },
  {
   "id": "x_sysadmin_scan",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "prole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:Scan"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "SystemAdmin"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:Scan"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "SystemAdmin"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
