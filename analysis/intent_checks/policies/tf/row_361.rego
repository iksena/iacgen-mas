package intent.tf.row_361

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pool": {
   "types": [
    "aws_cognito_user_pool"
   ],
   "where": []
  },
  "client": {
   "types": [
    "aws_cognito_user_pool_client"
   ],
   "where": []
  },
  "idpool": {
   "types": [
    "aws_cognito_identity_pool"
   ],
   "where": []
  },
  "rnd16": {
   "types": [
    "random_string",
    "random_password"
   ],
   "where": [
    {
     "path": [
      "length"
     ],
     "op": "eq",
     "value": 16
    }
   ]
  }
 },
 "checks": [
  {
   "id": "random_pet",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "random_pet"
    ],
    "where": []
   },
   "quote": "plus a randomly generated pet-name suffix"
  },
  {
   "id": "user_pool",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "quote": "a user pool"
  },
  {
   "id": "pool_name_underscores",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^[^-]+$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "(?i)replace"
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
        "value": "aws_cognito_user_pool"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "^\\$\\{(local|var)\\.[a-z_]*pool[a-z_]*name[a-z_]*\\}$|^\\$\\{(local|var)\\.[a-z_]*name[a-z_]*pool[a-z_]*\\}$"
     }
    }
   ],
   "quote": "hyphens in the name replaced by underscores",
   "justify": "the hyphen replacement is often done in a local the plan cannot show, so a pool name taken from a single named local or variable is accepted"
  },
  {
   "id": "mfa_off",
   "kind": "attr",
   "tier": "core",
   "select": "pool",
   "cond": {
    "path": [
     "mfa_configuration"
    ],
    "op": "eq",
    "value": "OFF"
   },
   "quote": "with MFA turned off",
   "justify": "MFA turned off is mfa_configuration OFF"
  },
  {
   "id": "auto_verify_email",
   "kind": "attr",
   "tier": "core",
   "select": "pool",
   "cond": {
    "path": [
     "auto_verified_attributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   },
   "quote": "email as an auto-verified attribute"
  },
  {
   "id": "schema_email",
   "kind": "attr",
   "tier": "core",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "email"
     },
     {
      "path": [
       "required"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "falsy"
     }
    ]
   },
   "quote": "a required immutable email attribute",
   "justify": "immutable means mutable false"
  },
  {
   "id": "schema_phone",
   "kind": "attr",
   "tier": "core",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)phone"
     },
     {
      "path": [
       "required"
      ],
      "op": "none_eq",
      "value": true
     },
     {
      "path": [
       "mutable"
      ],
      "op": "falsy"
     }
    ]
   },
   "quote": "an optional immutable phone number attribute",
   "justify": "optional means not required (false or omitted); immutable means mutable false"
  },
  {
   "id": "profile_user_id",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)user[_ -]?id"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_email",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)email"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_first_name",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(first[_ -]?name|given)"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_last_name",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(last[_ -]?name|family)"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_gender",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)gender"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_age",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(^|[_:.-])age$"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "profile_persona",
   "kind": "attr",
   "tier": "detail",
   "select": "pool",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)persona"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     }
    ]
   },
   "quote": "mutable string attributes for profile user ID, email, first name, last name, gender, age, and persona",
   "justify": "string attributes have data type String"
  },
  {
   "id": "sms_role",
   "kind": "ref",
   "tier": "core",
   "from": "pool",
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "SMS sending enabled through an IAM role that Cognito can assume"
  },
  {
   "id": "sms_role_trust",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-idp"
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
         "properties"
        ],
        "op": "regex",
        "value": "cognito-idp"
       }
      ]
     },
     "cond": {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "iam_role$|iam_policy_document"
     }
    }
   ],
   "quote": "an IAM role that Cognito can assume",
   "justify": "Cognito user pools assume roles as the cognito-idp service principal"
  },
  {
   "id": "ext_id_len",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "random_string",
     "random_password"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "length"
    ],
    "op": "eq",
    "value": 16
   },
   "quote": "with a random 16-character uppercase external ID"
  },
  {
   "id": "ext_id_upper",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "random_string",
     "random_password"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 16
     },
     {
      "path": [
       "upper"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "lower"
      ],
      "op": "falsy"
     }
    ]
   },
   "quote": "with a random 16-character uppercase external ID",
   "justify": "uppercase means upper true and lower false"
  },
  {
   "id": "ext_id_used",
   "kind": "ref",
   "tier": "detail",
   "from": "pool",
   "to": "rnd16",
   "quote": "with a random 16-character uppercase external ID"
  },
  {
   "id": "sns_publish",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)sns:(publish|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "sns:Publish"
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sns:(publish|\\*)"
       }
      ]
     },
     "cond": {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "iam_policy|iam_role|iam_policy_document|iam_group_policy"
     }
    }
   ],
   "quote": "a policy allowing it to publish to SNS"
  },
  {
   "id": "client",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "quote": "Add a user pool app client"
  },
  {
   "id": "client_no_secret",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "generate_secret"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "generate_secret"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "without a client secret"
  },
  {
   "id": "client_pool",
   "kind": "ref",
   "tier": "detail",
   "from": "client",
   "to": "pool",
   "quote": "Add a user pool app client"
  },
  {
   "id": "identity_pool",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_cognito_identity_pool"
    ],
    "where": []
   },
   "quote": "an identity pool"
  },
  {
   "id": "unauth_ids",
   "kind": "attr",
   "tier": "core",
   "select": "idpool",
   "cond": {
    "path": [
     "allow_unauthenticated_identities"
    ],
    "op": "truthy"
   },
   "quote": "an identity pool that allows unauthenticated identities"
  },
  {
   "id": "idpool_client",
   "kind": "ref",
   "tier": "core",
   "from": "idpool",
   "to": "client",
   "quote": "uses the user pool client as its identity provider"
  },
  {
   "id": "idpool_pool",
   "kind": "ref",
   "tier": "detail",
   "from": "idpool",
   "to": "pool",
   "quote": "uses the user pool client as its identity provider"
  },
  {
   "id": "roles_three",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "min": 3,
   "quote": "Attach two roles to the identity pool, a signed-users role for authenticated identities and an anonymous-users role for unauthenticated identities",
   "justify": "two identity-pool roles plus the SMS role"
  },
  {
   "id": "roles_attachment",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_cognito_identity_pool_roles_attachment"
    ],
    "where": []
   },
   "quote": "Attach two roles to the identity pool"
  },
  {
   "id": "roles_attach_pool",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_cognito_identity_pool_roles_attachment"
    ],
    "where": []
   },
   "to": "idpool",
   "quote": "Attach two roles to the identity pool"
  },
  {
   "id": "roles_attach_roles",
   "kind": "ref",
   "tier": "detail",
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
    "where": []
   },
   "quote": "a signed-users role for authenticated identities and an anonymous-users role for unauthenticated identities"
  },
  {
   "id": "roles_authenticated_key",
   "kind": "attr",
   "tier": "detail",
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
      "value": "aws_cognito_identity_pool_roles_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "roles"
    ],
    "op": "regex",
    "value": "(?i)(^|[^n])authenticated\"?:"
   },
   "quote": "a signed-users role for authenticated identities",
   "justify": "the attachment's roles map uses the key authenticated"
  },
  {
   "id": "roles_unauthenticated_key",
   "kind": "attr",
   "tier": "detail",
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
      "value": "aws_cognito_identity_pool_roles_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "roles"
    ],
    "op": "regex",
    "value": "(?i)unauthenticated\"?:"
   },
   "quote": "an anonymous-users role for unauthenticated identities",
   "justify": "the attachment's roles map uses the key unauthenticated"
  },
  {
   "id": "trust_federated",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cognito-identity"
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
         "properties"
        ],
        "op": "regex",
        "value": "cognito-identity"
       }
      ]
     },
     "cond": {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "iam_role$|iam_policy_document"
     }
    }
   ],
   "quote": "both trusting Cognito federated identities for this pool only",
   "justify": "Cognito federated identities are the cognito-identity service"
  },
  {
   "id": "trust_pool_scoped",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "to": "idpool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": "idpool"
    }
   ],
   "quote": "for this pool only"
  },
  {
   "id": "perm_identity",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cognito-identity:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "cognito-identity:*"
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cognito-identity:"
       }
      ]
     },
     "cond": {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "iam_policy|iam_role|iam_policy_document|iam_group_policy"
     }
    }
   ],
   "quote": "grant the authenticated role Cognito Identity and Cognito Sync permissions scoped to this identity pool",
   "justify": "Cognito Identity permissions are cognito-identity: actions"
  },
  {
   "id": "perm_sync",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cognito-sync:"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "cognito-sync:*"
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cognito-sync:"
       }
      ]
     },
     "cond": {
      "path": [
       "type"
      ],
      "op": "regex",
      "value": "iam_policy|iam_role|iam_policy_document|iam_group_policy"
     }
    }
   ],
   "quote": "Cognito Identity and Cognito Sync permissions",
   "justify": "Cognito Sync permissions are cognito-sync: actions"
  },
  {
   "id": "perm_scoped",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "to": "idpool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "idpool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": "idpool"
    }
   ],
   "quote": "scoped to this identity pool"
  },
  {
   "id": "x_web_identity",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "AssumeRoleWithWebIdentity"
     }
    ]
   },
   "cond": {
    "path": [
     "type"
    ],
    "op": "regex",
    "value": "iam_role$|iam_policy_document"
   }
  },
  {
   "id": "x_unauth_amr",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)unauthenticated"
     }
    ]
   },
   "cond": {
    "path": [
     "type"
    ],
    "op": "regex",
    "value": "iam_role$|iam_policy_document"
   }
  },
  {
   "id": "x_auth_amr",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)[^n]authenticated"
     }
    ]
   },
   "cond": {
    "path": [
     "type"
    ],
    "op": "regex",
    "value": "iam_role$|iam_policy_document"
   }
  },
  {
   "id": "extra_type_aws_iam_role_policy_attachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_role_policy_attachment"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
