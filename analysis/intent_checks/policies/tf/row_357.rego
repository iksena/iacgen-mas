package intent.tf.row_357

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "user_pool",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "coop-tweets"
     }
    ]
   },
   "tier": "core",
   "quote": "create a user pool named \"coop-tweets\""
  },
  {
   "id": "admin_only",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "admin_create_user_config",
     "*",
     "allow_admin_create_user_only"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "where only administrators can create users"
  },
  {
   "id": "pw_min_length",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "password_policy",
     "*",
     "minimum_length"
    ],
    "op": "gte",
    "value": 6
   },
   "tier": "core",
   "quote": "passwords must be at least 6 characters long",
   "justify": "at least 6 characters"
  },
  {
   "id": "pw_numbers",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "password_policy",
     "*",
     "require_numbers"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "include numbers, uppercase letters, and symbols"
  },
  {
   "id": "pw_uppercase",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "password_policy",
     "*",
     "require_uppercase"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "include numbers, uppercase letters, and symbols"
  },
  {
   "id": "pw_symbols",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "password_policy",
     "*",
     "require_symbols"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "include numbers, uppercase letters, and symbols"
  },
  {
   "id": "domain_prefix",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool_domain"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "domain"
    ],
    "op": "eq",
    "value": "coop-tweets-domain"
   },
   "tier": "core",
   "quote": "a hosted user pool domain with the prefix \"coop-tweets-domain\""
  },
  {
   "id": "domain_for_pool",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_user_pool_domain"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a hosted user pool domain"
  },
  {
   "id": "identity_pool_name",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_identity_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "identity_pool_name"
    ],
    "op": "eq",
    "value": "coop tweets"
   },
   "tier": "core",
   "quote": "an identity pool named \"coop tweets\""
  },
  {
   "id": "no_unauth_identities",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_identity_pool"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "allow_unauthenticated_identities"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_identity_pool"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "allow_unauthenticated_identities"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "does not allow unauthenticated identities"
  },
  {
   "id": "role_auth",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "coop-tweets_cognito_auth_role"
     }
    ]
   },
   "tier": "core",
   "quote": "\"coop-tweets_cognito_auth_role\" for authenticated identities"
  },
  {
   "id": "role_unauth",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "coop-tweets_cognito_unauth_role"
     }
    ]
   },
   "tier": "core",
   "quote": "\"coop-tweets_cognito_unauth_role\" for unauthenticated identities"
  },
  {
   "id": "attachment_auth_role",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_identity_pool_roles_attachment"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "coop-tweets_cognito_auth_role"
     }
    ]
   },
   "tier": "core",
   "quote": "attach two IAM roles to it"
  },
  {
   "id": "attachment_unauth_role",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_identity_pool_roles_attachment"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "coop-tweets_cognito_unauth_role"
     }
    ]
   },
   "tier": "core",
   "quote": "attach two IAM roles to it"
  },
  {
   "id": "attachment_to_pool",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_identity_pool_roles_attachment"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_cognito_identity_pool"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "attach two IAM roles to it"
  },
  {
   "id": "auth_role_trust_cognito",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "cognito-identity.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "cognito_auth_role$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "each trusting Cognito federated identities",
   "justify": "Cognito federated identities principal is cognito-identity.amazonaws.com (as the principal, not the :aud/:amr condition key)"
  },
  {
   "id": "unauth_role_trust_cognito",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "cognito-identity.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "cognito_unauth_role$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-identity\\.amazonaws\\.com([\"'\\]]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "each trusting Cognito federated identities",
   "justify": "Cognito federated identities principal is cognito-identity.amazonaws.com (as the principal, not the :aud/:amr condition key)"
  },
  {
   "id": "trust_this_pool_only",
   "kind": "ref",
   "tier": "core",
   "quote": "for this identity pool only",
   "justify": "'for this identity pool only' is the cognito-identity.amazonaws.com:aud condition naming this pool",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "in",
      "value": [
       "aws_iam_role",
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "cognito-identity\\.amazonaws\\.com:aud"
     }
    ]
   },
   "to": {
    "types": [
     "aws_cognito_identity_pool"
    ],
    "where": []
   }
  },
  {
   "id": "policy_auth",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "cognito_kibana_auth_coop-tweets"
     }
    ]
   },
   "tier": "core",
   "quote": "\"cognito_kibana_auth_coop-tweets\""
  },
  {
   "id": "policy_unauth",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "cognito_kibana_unauth_coop-tweets"
     }
    ]
   },
   "tier": "core",
   "quote": "\"cognito_kibana_unauth_coop-tweets\""
  },
  {
   "id": "auth_policy_attached",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_auth_coop-tweets"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_auth_coop-tweets"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_auth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_auth_coop-tweets"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "each granted a customer-managed policy"
  },
  {
   "id": "unauth_policy_attached",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_unauth_coop-tweets"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_unauth_coop-tweets"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "coop-tweets_cognito_unauth_role"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "cognito_kibana_unauth_coop-tweets"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "each granted a customer-managed policy"
  },
  {
   "id": "policy_mobileanalytics",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "mobileanalytics:(PutEvents|\\*)"
     },
     "quantifier": "all"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)mobileanalytics:(PutEvents|\\*)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "cognito_kibana_"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)mobileanalytics:(PutEvents|\\*)"
     }
    }
   ],
   "tier": "core",
   "quote": "allowing mobile analytics events and Cognito Sync and Cognito Identity actions",
   "justify": "mobile analytics events is mobileanalytics:PutEvents"
  },
  {
   "id": "policy_cognito_sync",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cognito-sync:"
     },
     "quantifier": "all"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cognito-sync:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "cognito_kibana_"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cognito-sync:"
     }
    }
   ],
   "tier": "core",
   "quote": "allowing mobile analytics events and Cognito Sync and Cognito Identity actions",
   "justify": "Cognito Sync actions use cognito-sync prefix"
  },
  {
   "id": "policy_cognito_identity",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cognito-identity:"
     },
     "quantifier": "all"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^cognito_kibana_(auth|unauth)_"
       }
      ]
     },
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cognito-identity:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "cognito_kibana_"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cognito-identity:"
     }
    }
   ],
   "tier": "core",
   "quote": "allowing mobile analytics events and Cognito Sync and Cognito Identity actions",
   "justify": "Cognito Identity actions use cognito-identity prefix"
  },
  {
   "id": "x_assume_webidentity",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "in",
      "value": [
       "aws_iam_role",
       "data.aws_iam_policy_document"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "sts:AssumeRoleWithWebIdentity"
   },
   "tier": "extra"
  },
  {
   "id": "x_amr_unauthenticated",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "in",
      "value": [
       "aws_iam_role",
       "data.aws_iam_policy_document"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "unauthenticated"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
