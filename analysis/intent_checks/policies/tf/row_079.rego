# GENERATED from specs/tf/row_079.json by intent_checks/build.py -- do not edit.
package intent.tf.row_079

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
   "id": "user_pool",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates a Cognito User Pool"
  },
  {
   "id": "app_client",
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
   "tier": "core",
   "quote": "a Cognito User Pool with an app client"
  },
  {
   "id": "identity_pool",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cognito_identity_pool"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "an Identity Pool"
  },
  {
   "id": "identity_pool_linked",
   "kind": "any_of",
   "tier": "core",
   "quote": "an Identity Pool linked to it",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cognito_identity_pool"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_cognito_user_pool_client"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cognito_identity_pool"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_cognito_user_pool"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "role_trusts_identity_pool",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM role that authenticated identities can assume",
   "checks": [
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "aws_cognito_identity_pool"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "cognito-identity.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "role",
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
    }
   ]
  },
  {
   "id": "role_attached_as_authenticated",
   "kind": "all_of",
   "tier": "core",
   "quote": "an IAM role that authenticated identities can assume",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cognito_identity_pool_roles_attachment"
      ],
      "where": []
     },
     "to": "role"
    },
    {
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
     }
    }
   ]
  },
  {
   "id": "cognito_sync_access",
   "kind": "any_of",
   "tier": "detail",
   "quote": "for Cognito Sync",
   "checks": [
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cognito-sync:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "contains",
      "value": "cognito-sync:"
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cognito-sync:"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "^(cognito-sync:.*|\\*)$"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "mobile_analytics_access",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Mobile Analytics access",
   "checks": [
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "mobileanalytics:"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "contains",
      "value": "mobileanalytics:"
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "mobileanalytics:"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "regex",
        "value": "^(mobileanalytics:.*|\\*)$"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy",
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
