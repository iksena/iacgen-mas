package intent.tf.row_269

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "pool_named",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "box_things"
   },
   "quote": "Amazon Cognito user pool named \"box_things\""
  },
  {
   "id": "email_alias",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "alias_attributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
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
       "alias_attributes"
      ],
      "op": "contains",
      "value": "email"
     }
    }
   ],
   "quote": "uses email as an alias"
  },
  {
   "id": "auto_verify_email",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "auto_verified_attributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   },
   "quote": "auto-verifies email"
  },
  {
   "id": "confirm_link",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "verification_message_template",
     "*",
     "default_email_option"
    ],
    "op": "eq",
    "value": "CONFIRM_WITH_LINK"
   },
   "quote": "via a confirmation link"
  },
  {
   "id": "pw_min_length",
   "tier": "core",
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
    "op": "eq",
    "value": 8
   },
   "quote": "enforces a strong 8-character password policy"
  },
  {
   "id": "pw_strong",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
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
       "require_lowercase"
      ],
      "op": "truthy"
     }
    },
    {
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
     }
    },
    {
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
     }
    },
    {
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
     }
    }
   ],
   "quote": "enforces a strong 8-character password policy",
   "justify": "strong password policy implies all four character classes are required"
  },
  {
   "id": "mfa_off",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "mfa_configuration"
    ],
    "op": "eq",
    "value": "OFF"
   },
   "quote": "MFA turned off"
  },
  {
   "id": "self_signup",
   "tier": "core",
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
    "op": "none_eq",
    "value": true
   },
   "quote": "allows self sign-up",
   "justify": "self sign-up means admin-only user creation is not enforced"
  },
  {
   "id": "client_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "quote": "app client named \"box_things_client\""
  },
  {
   "id": "client_named",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "box_things_client"
   },
   "quote": "app client named \"box_things_client\""
  },
  {
   "id": "client_of_pool",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "quote": "Also create an app client"
  },
  {
   "id": "access_60_min",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "access_token_validity"
        ],
        "op": "eq",
        "value": 60
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "access_token"
      ],
      "op": "eq",
      "value": "minutes"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "access_token_validity"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "access_token"
      ],
      "op": "eq",
      "value": "hours"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "access_token_validity"
        ],
        "op": "eq",
        "value": 3600
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "access_token"
      ],
      "op": "eq",
      "value": "seconds"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "access_token_validity"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "access_token"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "60-minute access and ID tokens",
   "justify": "60 minutes equals 1 hour (the default unit when token_validity_units is omitted) or 3600 seconds"
  },
  {
   "id": "id_60_min",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "id_token_validity"
        ],
        "op": "eq",
        "value": 60
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "id_token"
      ],
      "op": "eq",
      "value": "minutes"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "id_token_validity"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "id_token"
      ],
      "op": "eq",
      "value": "hours"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "id_token_validity"
        ],
        "op": "eq",
        "value": 3600
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "id_token"
      ],
      "op": "eq",
      "value": "seconds"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": [
       {
        "path": [
         "id_token_validity"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "cond": {
      "path": [
       "token_validity_units",
       "*",
       "id_token"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "60-minute access and ID tokens",
   "justify": "60 minutes equals 1 hour (the default unit when token_validity_units is omitted) or 3600 seconds"
  },
  {
   "id": "auth_flows",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "explicit_auth_flows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_)?USER_PASSWORD_AUTH$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "explicit_auth_flows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_ADMIN_USER_PASSWORD_AUTH|ADMIN_NO_SRP_AUTH)$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "explicit_auth_flows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_)?USER_SRP_AUTH$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "explicit_auth_flows",
       "*"
      ],
      "op": "regex",
      "value": "(?i)^(ALLOW_)?REFRESH_TOKEN_AUTH$"
     }
    }
   ],
   "quote": "supports user-password, admin user-password, SRP, and refresh-token authentication flows",
   "justify": "ADMIN_NO_SRP_AUTH is the legacy name of the admin user-password flow"
  },
  {
   "id": "callback_url",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "callback_urls",
     "*"
    ],
    "op": "regex",
    "value": "^https?://"
   },
   "quote": "a sample callback and logout URL",
   "justify": "a sample callback URL is an http(s) URL"
  },
  {
   "id": "logout_url",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "logout_urls",
     "*"
    ],
    "op": "regex",
    "value": "^https?://"
   },
   "quote": "a sample callback and logout URL",
   "justify": "a sample logout URL is an http(s) URL"
  },
  {
   "id": "x_idp_cognito",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool_client"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "supported_identity_providers",
     "*"
    ],
    "op": "eq",
    "value": "COGNITO"
   }
  },
  {
   "id": "x_recovery_email",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "account_recovery_setting",
     "*",
     "recovery_mechanism",
     "*",
     "name"
    ],
    "op": "eq",
    "value": "verified_email"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
