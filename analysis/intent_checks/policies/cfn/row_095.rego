package intent.cfn.row_095

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
  "idp": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": []
  },
  "cog_roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "cognito-identity\\.amazonaws\\.com"
    }
   ]
  },
  "auth_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "cognito-identity\\.amazonaws\\.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition",
      "*",
      "cognito-identity.amazonaws.com:amr"
     ],
     "op": "none_eq",
     "value": "unauthenticated"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition",
      "*",
      "cognito-identity.amazonaws.com:amr",
      "*"
     ],
     "op": "none_eq",
     "value": "unauthenticated"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "user_pool",
   "tier": "core",
   "kind": "exists",
   "select": "pool",
   "quote": "a user pool with multi-factor authentication enabled"
  },
  {
   "id": "app_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "UserPoolName"
      ],
      "op": "regex",
      "value": "(?i)nih-grants"
     }
    },
    {
     "kind": "attr",
     "select": "idp",
     "cond": {
      "path": [
       "IdentityPoolName"
      ],
      "op": "regex",
      "value": "(?i)nih-grants"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "regex",
        "value": "(?i)nih-grants"
       }
      ]
     }
    }
   ],
   "quote": "for an application called \"nih-grants\""
  },
  {
   "id": "advanced_security",
   "tier": "core",
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
   "quote": "advanced security mode enforced"
  },
  {
   "id": "identity_pool",
   "tier": "core",
   "kind": "exists",
   "select": "idp",
   "quote": "an identity pool that supports both authenticated and unauthenticated identities"
  },
  {
   "id": "unauth_disabled",
   "tier": "core",
   "kind": "attr",
   "select": "idp",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": "false"
   },
   "quote": "with unauthenticated access disabled by default",
   "justify": "disabled = false"
  },
  {
   "id": "app_clients",
   "tier": "core",
   "kind": "exists",
   "select": "clients",
   "min": 2,
   "quote": "two app clients (one for web and one for general use)",
   "justify": "two app clients = at least 2"
  },
  {
   "id": "refresh_30_days",
   "tier": "core",
   "kind": "attr",
   "select": "clients",
   "cond": {
    "path": [
     "RefreshTokenValidity"
    ],
    "op": "eq",
    "value": 30
   },
   "quantifier": "all",
   "quote": "with a 30-day refresh token validity",
   "justify": "30-day refresh validity"
  },
  {
   "id": "min_length",
   "tier": "core",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "Policies",
     "PasswordPolicy",
     "MinimumLength"
    ],
    "op": "eq",
    "value": 11
   },
   "quote": "a password policy requiring a minimum length of 11 characters"
  },
  {
   "id": "char_classes",
   "tier": "core",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "Policies",
     "PasswordPolicy"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "RequireUppercase"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "RequireLowercase"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "RequireNumbers"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "RequireSymbols"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "including uppercase, lowercase, numbers, and symbols"
  },
  {
   "id": "temp_password_days",
   "tier": "detail",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "Policies",
     "PasswordPolicy",
     "TemporaryPasswordValidityDays"
    ],
    "op": "eq",
    "value": 7
   },
   "quote": "with temporary passwords valid for 7 days"
  },
  {
   "id": "confirm_with_code",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "VerificationMessageTemplate",
       "DefaultEmailOption"
      ],
      "op": "eq",
      "value": "CONFIRM_WITH_CODE"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "VerificationMessageTemplate",
       "DefaultEmailOption"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "email verification should use a confirmation code",
   "justify": "CONFIRM_WITH_CODE is the Cognito default when unset"
  },
  {
   "id": "verification_subject",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "EmailVerificationSubject"
      ],
      "op": "regex",
      "value": "(?i)^Your verification code$"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "VerificationMessageTemplate",
       "EmailSubject"
      ],
      "op": "regex",
      "value": "(?i)^Your verification code$"
     }
    }
   ],
   "quote": "the subject \"Your verification code\""
  },
  {
   "id": "verification_message",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "EmailVerificationMessage"
      ],
      "op": "regex",
      "value": "(?i)^Your verification code is \\{####\\}$"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "VerificationMessageTemplate",
       "EmailMessage"
      ],
      "op": "regex",
      "value": "(?i)^Your verification code is \\{####\\}$"
     }
    }
   ],
   "quote": "message \"Your verification code is {####}\""
  },
  {
   "id": "s3_put",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:PutObject"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObject"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting S3 object-level permissions (put, get, delete, and tagging)"
  },
  {
   "id": "s3_get",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:GetObject"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting S3 object-level permissions (put, get, delete, and tagging)"
  },
  {
   "id": "s3_delete",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:DeleteObject"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:DeleteObject"
       }
      ]
     }
    }
   ],
   "quote": "an inline policy granting S3 object-level permissions (put, get, delete, and tagging)"
  },
  {
   "id": "s3_tagging",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:PutObjectTagging"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObjectTagging"
       }
      ]
     }
    }
   ],
   "quote": "S3 object-level permissions (put, get, delete, and tagging)"
  },
  {
   "id": "s3_bucket_scope",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:PutObject"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "nih-grants-context"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "nih-grants-context"
       }
      ]
     }
    }
   ],
   "quote": "on a bucket named with the pattern \"nih-grants-context-{region}-{accountId}\""
  },
  {
   "id": "kms_generate_data_key",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:GenerateDataKey"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:GenerateDataKey"
       }
      ]
     }
    }
   ],
   "quote": "KMS GenerateDataKey and Decrypt permissions"
  },
  {
   "id": "kms_decrypt",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:Decrypt"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:Decrypt"
       }
      ]
     }
    }
   ],
   "quote": "KMS GenerateDataKey and Decrypt permissions"
  },
  {
   "id": "kms_alias_condition",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:Decrypt"
         },
         {
          "path": [
           "Condition"
          ],
          "op": "regex",
          "value": "nih-grants-s3-key"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:Decrypt"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "nih-grants-s3-key"
       }
      ]
     }
    }
   ],
   "quote": "restricted to requests using the alias \"nih-grants-s3-key\""
  },
  {
   "id": "websocket_connect",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
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
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "execute-api:Invoke"
         }
        ]
       }
      ]
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
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
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "execute-api:Invoke"
       }
      ]
     }
    }
   ],
   "quote": "API Gateway WebSocket connect permission on any API in the account and region",
   "justify": "WebSocket connect is authorised via execute-api:Invoke on the $connect route"
  },
  {
   "id": "policy_on_cognito_role",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "auth_role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "to": "auth_role"
    },
    {
     "kind": "attr",
     "select": "auth_role",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "The authenticated IAM role should include an inline policy"
  },
  {
   "id": "role_attachment",
   "tier": "core",
   "kind": "exists",
   "select": "attach",
   "quote": "the authenticated and unauthenticated roles should be attached via a role mapping"
  },
  {
   "id": "attached_roles",
   "tier": "core",
   "kind": "attr",
   "select": "attach",
   "cond": {
    "path": [
     "Roles"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "authenticated"
      ],
      "op": "present"
     },
     {
      "path": [
       "unauthenticated"
      ],
      "op": "present"
     }
    ]
   },
   "quote": "the authenticated and unauthenticated roles should be attached via a role mapping"
  },
  {
   "id": "attachment_to_pool",
   "tier": "detail",
   "kind": "ref",
   "from": "attach",
   "to": "idp",
   "quote": "The identity pool must be linked to both app clients and the authenticated and unauthenticated roles should be attached via a role mapping"
  },
  {
   "id": "pool_two_providers",
   "tier": "core",
   "kind": "attr",
   "select": "idp",
   "cond": {
    "path": [
     "CognitoIdentityProviders"
    ],
    "op": "len_gte",
    "value": 2
   },
   "quote": "The identity pool must be linked to both app clients",
   "justify": "both app clients = two providers"
  },
  {
   "id": "pool_linked_clients",
   "tier": "detail",
   "kind": "ref",
   "from": "idp",
   "to": "clients",
   "quote": "The identity pool must be linked to both app clients"
  },
  {
   "id": "x_trust_web_identity",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "AssumeRoleWithWebIdentity"
   }
  },
  {
   "id": "x_email_required",
   "tier": "extra",
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
     }
    ]
   }
  },
  {
   "id": "x_username_case_insensitive",
   "tier": "extra",
   "kind": "attr",
   "select": "pool",
   "cond": {
    "path": [
     "UsernameConfiguration",
     "CaseSensitive"
    ],
    "op": "falsy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
