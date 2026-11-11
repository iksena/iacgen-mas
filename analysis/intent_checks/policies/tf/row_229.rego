package intent.tf.row_229

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "test_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test_role"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_named",
   "tier": "core",
   "kind": "attr",
   "select": "test_role",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "test_role"
   },
   "quote": "a service-catalog-assumable IAM role named test_role"
  },
  {
   "id": "role_trust_sc",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "test_role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "servicecatalog.amazonaws.com"
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
      "op": "contains",
      "value": "servicecatalog.amazonaws.com"
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
       "properties",
       "statement"
      ],
      "op": "contains",
      "value": "servicecatalog.amazonaws.com"
     }
    }
   ],
   "quote": "service-catalog-assumable IAM role",
   "justify": "Service Catalog assumable means the trust policy names the servicecatalog.amazonaws.com principal"
  },
  {
   "id": "launch_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
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
       "inline_policy"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "with a scoped launch-constraint policy"
  },
  {
   "id": "policy_on_role",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": "test_role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "test_role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": "test_role"
    },
    {
     "kind": "attr",
     "select": "test_role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "from": "test_role",
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     }
    }
   ],
   "quote": "a service-catalog-assumable IAM role named test_role with a scoped launch-constraint policy"
  },
  {
   "id": "group_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "quote": "plus an IAM group"
  },
  {
   "id": "user_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "a console-enabled user"
  },
  {
   "id": "console_login",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_user_login_profile"
    ],
    "where": []
   },
   "quote": "console-enabled user",
   "justify": "console access for an IAM user is granted by a login profile"
  },
  {
   "id": "login_for_user",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_user_login_profile"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "a console-enabled user"
  },
  {
   "id": "member_of_group",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "added as a member of that group"
  },
  {
   "id": "member_of_user",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    }
   ],
   "quote": "a console-enabled user added as a member of that group"
  },
  {
   "id": "x_group_policy",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_group_policy_attachment"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "policy_arn"
    ],
    "op": "contains",
    "value": "AWSServiceCatalogEndUserFullAccess"
   }
  },
  {
   "id": "x_launch_sc_actions",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "servicecatalog:"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "servicecatalog:"
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
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "servicecatalog:"
     }
    }
   ]
  },
  {
   "id": "x_user_force_destroy",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "eq",
    "value": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
