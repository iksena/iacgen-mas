package intent.tf.row_344

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "quote": "creates an IAM role for GitHub Actions to assume through OpenID Connect web identity federation"
  },
  {
   "id": "webid",
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
      "value": "(?i)sts:AssumeRoleWithWebIdentity|sts:\\*"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)sts:AssumeRoleWithWebIdentity|sts:\\*"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i)sts:AssumeRoleWithWebIdentity|sts:\\*"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "(?i)sts:AssumeRoleWithWebIdentity|sts:\\*"
       }
      ]
     }
    }
   ],
   "quote": "assume through OpenID Connect web identity federation"
  },
  {
   "id": "github_idp",
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
      "value": "token\\.actions\\.githubusercontent\\.com"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "token\\.actions\\.githubusercontent\\.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "token\\.actions\\.githubusercontent\\.com"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "token\\.actions\\.githubusercontent\\.com"
       }
      ]
     }
    }
   ],
   "quote": "trusting the GitHub OIDC identity provider (\"token.actions.githubusercontent.com\")"
  },
  {
   "id": "current_account",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
        "value": "data.aws_caller_identity"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_openid_connect_provider"
      ],
      "where": [
       {
        "path": [
         "url"
        ],
        "op": "contains",
        "value": "token.actions.githubusercontent.com"
       }
      ]
     }
    },
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
      "value": "arn:aws:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com"
     }
    }
   ],
   "quote": "in the current account"
  },
  {
   "id": "cond_iss",
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
      "value": "(?i):iss\\b"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i):iss\\b"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i):iss\\b"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "(?i):iss\\b"
       }
      ]
     }
    }
   ],
   "quote": "with issuer and audience (\"sts.amazonaws.com\") conditions plus a subject condition"
  },
  {
   "id": "cond_aud",
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
      "value": "(?i):aud\\b"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i):aud\\b"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i):aud\\b"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "(?i):aud\\b"
       }
      ]
     }
    }
   ],
   "quote": "with issuer and audience (\"sts.amazonaws.com\") conditions plus a subject condition"
  },
  {
   "id": "aud_value",
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
      "value": "sts\\.amazonaws\\.com"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "sts\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "sts\\.amazonaws\\.com"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "sts\\.amazonaws\\.com"
       }
      ]
     }
    }
   ],
   "quote": "with issuer and audience (\"sts.amazonaws.com\") conditions plus a subject condition"
  },
  {
   "id": "cond_sub",
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
      "value": "(?i):sub\\b"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i):sub\\b"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
         "properties",
         "statement"
        ],
        "op": "regex",
        "value": "(?i):sub\\b"
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
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement"
        ],
        "op": "regex",
        "value": "(?i):sub\\b"
       }
      ]
     }
    }
   ],
   "quote": "with issuer and audience (\"sts.amazonaws.com\") conditions plus a subject condition"
  },
  {
   "id": "subjects_list_empty",
   "kind": "attr",
   "tier": "detail",
   "quote": "a configurable list of repository patterns that is empty by default",
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
      "value": "(?i)subject|repo|pattern"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "len_eq",
    "value": 0
   }
  },
  {
   "id": "role_path",
   "kind": "attr",
   "tier": "core",
   "select": "role",
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quote": "The role should use path \"/\""
  },
  {
   "id": "force_detach",
   "kind": "attr",
   "tier": "core",
   "select": "role",
   "cond": {
    "path": [
     "force_detach_policies"
    ],
    "op": "truthy"
   },
   "quote": "force-detach policies on destroy"
  },
  {
   "id": "no_managed_policies",
   "tier": "core",
   "quote": "attach no managed policies by default",
   "kind": "all_of",
   "justify": "no attachment resource is created by default (every selected attachment would carry a role), and the role sets no managed_policy_arns",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role",
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "role"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "roles"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "managed_policy_arns"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "out_arn",
   "kind": "ref",
   "tier": "detail",
   "quote": "output its ARN, name, path, and unique ID",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(^|_)arn$"
     }
    ]
   },
   "to": "role"
  },
  {
   "id": "out_name",
   "kind": "ref",
   "tier": "detail",
   "quote": "output its ARN, name, path, and unique ID",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(^|_)name$"
     }
    ]
   },
   "to": "role"
  },
  {
   "id": "out_path",
   "kind": "ref",
   "tier": "detail",
   "quote": "output its ARN, name, path, and unique ID",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(^|_)path$"
     }
    ]
   },
   "to": "role"
  },
  {
   "id": "out_unique",
   "kind": "ref",
   "tier": "detail",
   "quote": "output its ARN, name, path, and unique ID",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)unique_?id$"
     }
    ]
   },
   "to": "role"
  },
  {
   "id": "x_tags_session",
   "kind": "attr",
   "tier": "extra",
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
    "value": "(?i)sts:TagSession"
   }
  },
  {
   "id": "extra_type_aws_iam_role_policy_attachment",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_iam_role_policy_attachment"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
