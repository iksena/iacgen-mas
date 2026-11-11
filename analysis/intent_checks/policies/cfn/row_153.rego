package intent.cfn.row_153

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "up": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "client": {
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
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "role_cog": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
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
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)[^n]authenticated"
    }
   ]
  },
  "unauth_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "(?i)unauthenticated"
    }
   ]
  },
  "output": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "not_unauth_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Federated",
      "*"
     ],
     "op": "eq",
     "value": "cognito-identity.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Condition",
      "*",
      "*"
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
      "*",
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
   "select": "up",
   "quote": "a Cognito user pool with email as the username alias"
  },
  {
   "id": "email_alias",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "up",
     "cond": {
      "path": [
       "AliasAttributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    },
    {
     "kind": "attr",
     "select": "up",
     "cond": {
      "path": [
       "UsernameAttributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    }
   ],
   "quote": "email as the username alias",
   "justify": "email as the username alias = AliasAttributes or UsernameAttributes email"
  },
  {
   "id": "auto_verify",
   "tier": "core",
   "kind": "attr",
   "select": "up",
   "cond": {
    "path": [
     "AutoVerifiedAttributes",
     "*"
    ],
    "op": "eq",
    "value": "email"
   },
   "quote": "auto-verified email"
  },
  {
   "id": "required_attrs",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "up",
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
        "value": "given_name"
       },
       {
        "path": [
         "Required"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "up",
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
        "value": "family_name"
       },
       {
        "path": [
         "Required"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "up",
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
        "value": true
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "up",
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
        "value": "preferred_username"
       },
       {
        "path": [
         "Required"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ],
   "quote": "requiring given_name, family_name, email, and preferred_username as required attributes"
  },
  {
   "id": "client",
   "tier": "core",
   "kind": "exists",
   "select": "client",
   "quote": "a user pool client with no secret"
  },
  {
   "id": "client_no_secret",
   "tier": "core",
   "kind": "attr",
   "select": "client",
   "cond": {
    "path": [
     "GenerateSecret"
    ],
    "op": "none_eq",
    "value": "true"
   },
   "quote": "a user pool client with no secret"
  },
  {
   "id": "client_pool",
   "tier": "core",
   "kind": "ref",
   "from": "client",
   "to": "up",
   "quote": "a user pool client with no secret"
  },
  {
   "id": "identity_pool",
   "tier": "core",
   "kind": "exists",
   "select": "idp",
   "quote": "a Cognito identity pool that allows unauthenticated identities"
  },
  {
   "id": "allow_unauth",
   "tier": "core",
   "kind": "attr",
   "select": "idp",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "a Cognito identity pool that allows unauthenticated identities"
  },
  {
   "id": "idp_linked",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "idp",
     "to": "up"
    },
    {
     "kind": "ref",
     "from": "idp",
     "to": "client"
    }
   ],
   "quote": "is linked to the user pool"
  },
  {
   "id": "idp_name",
   "tier": "core",
   "kind": "attr",
   "select": "idp",
   "cond": {
    "path": [
     "IdentityPoolName"
    ],
    "op": "eq",
    "value": "identity pool"
   },
   "quote": "the identity pool name (default \"identity pool\")"
  },
  {
   "id": "idp_name_param",
   "tier": "detail",
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
      "op": "eq",
      "value": "identity pool"
     }
    ]
   },
   "quote": "the identity pool name (default \"identity pool\")"
  },
  {
   "id": "role_attachment",
   "tier": "core",
   "kind": "exists",
   "select": "attach",
   "quote": "identity pool role attachments"
  },
  {
   "id": "attachment_pool",
   "tier": "core",
   "kind": "ref",
   "from": "attach",
   "to": "idp",
   "quote": "identity pool role attachments"
  },
  {
   "id": "attachment_roles",
   "tier": "core",
   "kind": "all_of",
   "quote": "identity pool role attachments and separate IAM roles for authenticated and unauthenticated users",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": "role_cog"
    },
    {
     "kind": "attr",
     "select": "attach",
     "cond": {
      "path": [
       "Roles",
       "authenticated"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "attach",
     "cond": {
      "path": [
       "Roles",
       "unauthenticated"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "cognito_roles",
   "tier": "core",
   "kind": "exists",
   "select": "role_cog",
   "min": 2,
   "quote": "separate IAM roles for authenticated and unauthenticated users, each with appropriate trust policies for Cognito",
   "justify": "one role for authenticated and one for unauthenticated users"
  },
  {
   "id": "auth_role",
   "tier": "detail",
   "kind": "exists",
   "select": "auth_role",
   "quote": "separate IAM roles for authenticated and unauthenticated users, each with appropriate trust policies for Cognito"
  },
  {
   "id": "unauth_role",
   "tier": "detail",
   "kind": "exists",
   "select": "unauth_role",
   "quote": "separate IAM roles for authenticated and unauthenticated users, each with appropriate trust policies for Cognito"
  },
  {
   "id": "lex_v1_posttext",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
      "value": "lex:PostText"
     },
     "quantifier": "all"
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
        "value": "lex:PostText"
       }
      ]
     },
     "to": "role_cog"
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
        "value": "lex:PostText"
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ],
   "quote": "policies that grant either Lex V1 actions (like PostText and PostContent)"
  },
  {
   "id": "lex_v1_postcontent",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_cog",
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
      "value": "lex:PostContent"
     },
     "quantifier": "all"
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
        "value": "lex:PostContent"
       }
      ]
     },
     "to": "role_cog"
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
        "value": "lex:PostContent"
       }
      ]
     },
     "to": "role_cog",
     "bidirectional": true
    }
   ],
   "quote": "policies that grant either Lex V1 actions (like PostText and PostContent)"
  },
  {
   "id": "lex_v2_actions",
   "tier": "core",
   "kind": "any_of",
   "quote": "or Lex V2 actions (like RecognizeText and RecognizeUtterance) based on a condition",
   "justify": "V2 policies in a gated resource are matched as declared; V2 statements inside Fn::If are resolved away under default conditions, so a parameter named for the V2 bot stands in",
   "checks": [
    {
     "kind": "exists",
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
         "AWS::IAM::Role",
         "AWS::IAM::Policy",
         "AWS::IAM::ManagedPolicy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)lex:(RecognizeText|RecognizeUtterance)"
       }
      ]
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)(v2.*bot|bot.*v2)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "polly_auth",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "not_unauth_role",
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
      "value": "polly:SynthesizeSpeech"
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
        "value": "polly:SynthesizeSpeech"
       }
      ]
     },
     "to": "not_unauth_role"
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
        "value": "polly:SynthesizeSpeech"
       }
      ]
     },
     "to": "not_unauth_role",
     "bidirectional": true
    }
   ],
   "quote": "plus a Polly synthesise speech permission for authenticated roles",
   "justify": "synthesise speech = polly:SynthesizeSpeech"
  },
  {
   "id": "lex_bot_default",
   "tier": "detail",
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
      "op": "eq",
      "value": "OrderFlowers"
     }
    ]
   },
   "quote": "the Lex V1 bot name (default \"OrderFlowers\")"
  },
  {
   "id": "lex_v2_params",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
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
        "op": "regex",
        "value": "(?i)bot.?id"
       }
      ]
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)alias.?id"
       }
      ]
     }
    }
   ],
   "quote": "optional Lex V2 bot ID and alias ID"
  },
  {
   "id": "force_login_param",
   "tier": "detail",
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
      "value": "ForceCognitoLogin"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    ]
   },
   "quote": "a ForceCognitoLogin flag (default false)"
  },
  {
   "id": "live_chat_param",
   "tier": "detail",
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
      "value": "ShouldEnableLiveChat"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    ]
   },
   "quote": "a ShouldEnableLiveChat flag (default false)"
  },
  {
   "id": "out_identity_pool",
   "tier": "detail",
   "kind": "ref",
   "from": "output",
   "to": "idp",
   "quote": "export the identity pool ID, user pool ID, and user pool client ID as outputs"
  },
  {
   "id": "out_user_pool",
   "tier": "detail",
   "kind": "ref",
   "from": "output",
   "to": "up",
   "quote": "export the identity pool ID, user pool ID, and user pool client ID as outputs"
  },
  {
   "id": "out_client",
   "tier": "detail",
   "kind": "ref",
   "from": "output",
   "to": "client",
   "quote": "export the identity pool ID, user pool ID, and user pool client ID as outputs"
  },
  {
   "id": "x_assume_web_identity",
   "tier": "extra",
   "kind": "attr",
   "select": "role_cog",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "eq",
    "value": "sts:AssumeRoleWithWebIdentity"
   },
   "quantifier": "all"
  },
  {
   "id": "x_mfa_off",
   "tier": "extra",
   "kind": "attr",
   "select": "up",
   "cond": {
    "path": [
     "MfaConfiguration"
    ],
    "op": "eq",
    "value": "OFF"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
