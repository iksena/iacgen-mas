package intent.tf.row_036

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "pool",
   "tier": "core",
   "quote": "creates an Amazon Cognito User Pool named \"identity pool\"",
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
      "value": "identity pool"
     }
    ]
   }
  },
  {
   "id": "role",
   "tier": "core",
   "quote": "The IAM role must be named \"user-group-role\"",
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
      "value": "user-group-role"
     }
    ]
   }
  },
  {
   "id": "group",
   "tier": "core",
   "quote": "provision a user group named \"user-group\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cognito_user_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-group"
     }
    ]
   }
  },
  {
   "id": "group_pool",
   "tier": "core",
   "quote": "attached to the user pool and IAM role",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_user_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-group"
     }
    ]
   },
   "to": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   }
  },
  {
   "id": "group_role",
   "tier": "core",
   "quote": "attached to the user pool and IAM role",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_user_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-group"
     }
    ]
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   }
  },
  {
   "id": "group_desc",
   "tier": "detail",
   "quote": "configured with the description \"Managed by Terraform\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-group"
     }
    ]
   },
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "Managed by Terraform"
   }
  },
  {
   "id": "group_precedence",
   "tier": "core",
   "quote": "a precedence value of 42",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-group"
     }
    ]
   },
   "cond": {
    "path": [
     "precedence"
    ],
    "op": "eq",
    "value": 42
   }
  },
  {
   "id": "trust_federated",
   "tier": "core",
   "quote": "a trust policy allowing federated access from \"cognito-identity.amazonaws.com\"",
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
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)(federated[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?cognito-identity\\.amazonaws\\.com|identifiers:\\[cognito-identity\\.amazonaws\\.com\\][^\\]]{0,40}type:federated)"
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
        "op": "eq",
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)(federated[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?cognito-identity\\.amazonaws\\.com|identifiers:\\[cognito-identity\\.amazonaws\\.com\\][^\\]]{0,40}type:federated)"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(federated[\"']?\\s*[:=]\\s*\\[?\\s*[\"']?cognito-identity\\.amazonaws\\.com|identifiers:\\[cognito-identity\\.amazonaws\\.com\\][^\\]]{0,40}type:federated)"
     }
    }
   ]
  },
  {
   "id": "trust_action",
   "tier": "core",
   "quote": "using the sts:AssumeRoleWithWebIdentity action",
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
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "sts:AssumeRoleWithWebIdentity"
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
        "op": "eq",
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "sts:AssumeRoleWithWebIdentity"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "sts:AssumeRoleWithWebIdentity"
     }
    }
   ]
  },
  {
   "id": "trust_aud",
   "tier": "core",
   "quote": "require the audience to equal \"us-east-1:12345678-dead-beef-cafe-123456790ab\"",
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
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?s)(cognito-identity\\.amazonaws\\.com:aud.{0,300}us-east-1:12345678-dead-beef-cafe-123456790ab|us-east-1:12345678-dead-beef-cafe-123456790ab.{0,300}cognito-identity\\.amazonaws\\.com:aud)"
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
        "op": "eq",
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?s)(cognito-identity\\.amazonaws\\.com:aud.{0,300}us-east-1:12345678-dead-beef-cafe-123456790ab|us-east-1:12345678-dead-beef-cafe-123456790ab.{0,300}cognito-identity\\.amazonaws\\.com:aud)"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?s)(cognito-identity\\.amazonaws\\.com:aud.{0,300}us-east-1:12345678-dead-beef-cafe-123456790ab|us-east-1:12345678-dead-beef-cafe-123456790ab.{0,300}cognito-identity\\.amazonaws\\.com:aud)"
     }
    }
   ]
  },
  {
   "id": "trust_amr",
   "tier": "core",
   "quote": "the authentication method reference to include \"authenticated\"",
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
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?is)(cognito-identity\\.amazonaws\\.com:amr.{0,300}[^a-z]authenticated|[^a-z]authenticated.{0,300}cognito-identity\\.amazonaws\\.com:amr)"
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
        "op": "eq",
        "value": "user-group-role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?is)(cognito-identity\\.amazonaws\\.com:amr.{0,300}[^a-z]authenticated|[^a-z]authenticated.{0,300}cognito-identity\\.amazonaws\\.com:amr)"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)(cognito-identity\\.amazonaws\\.com:amr.{0,300}[^a-z]authenticated|[^a-z]authenticated.{0,300}cognito-identity\\.amazonaws\\.com:amr)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
