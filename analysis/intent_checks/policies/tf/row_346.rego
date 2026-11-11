package intent.tf.row_346

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "billing_g": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "BillingGroup"
    }
   ]
  },
  "billing_u": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Billing"
    }
   ]
  },
  "billing_lp": {
   "types": [
    "aws_iam_user_login_profile"
   ],
   "where": [
    {
     "path": [
      "user"
     ],
     "op": "eq",
     "value": "Billing"
    }
   ]
  },
  "billing_att": {
   "types": [
    "aws_iam_group_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "group"
     ],
     "op": "eq",
     "value": "BillingGroup"
    }
   ]
  },
  "billing_pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "BillingPolicy"
    }
   ]
  },
  "billing_pol_decl": {
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
     "op": "eq",
     "value": "BillingPolicy"
    }
   ]
  },
  "admin_g": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "AdminGroup"
    }
   ]
  },
  "admin_u": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Admin"
    }
   ]
  },
  "admin_lp": {
   "types": [
    "aws_iam_user_login_profile"
   ],
   "where": [
    {
     "path": [
      "user"
     ],
     "op": "eq",
     "value": "Admin"
    }
   ]
  },
  "admin_att": {
   "types": [
    "aws_iam_group_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "group"
     ],
     "op": "eq",
     "value": "AdminGroup"
    }
   ]
  },
  "suport_g": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "SuportGroup"
    }
   ]
  },
  "suport_u": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Suport"
    }
   ]
  },
  "suport_lp": {
   "types": [
    "aws_iam_user_login_profile"
   ],
   "where": [
    {
     "path": [
      "user"
     ],
     "op": "eq",
     "value": "Suport"
    }
   ]
  },
  "suport_att": {
   "types": [
    "aws_iam_group_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "group"
     ],
     "op": "eq",
     "value": "SuportGroup"
    }
   ]
  },
  "suport_pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "SuportPolicy"
    }
   ]
  },
  "suport_pol_decl": {
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
     "op": "eq",
     "value": "SuportPolicy"
    }
   ]
  },
  "outputs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "billing_inl": {
   "types": [
    "aws_iam_group_policy"
   ],
   "where": [
    {
     "path": [
      "group"
     ],
     "op": "eq",
     "value": "BillingGroup"
    },
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "BillingPolicy"
    }
   ]
  },
  "billing_inl_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_iam_group_policy"
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "eq",
     "value": "BillingPolicy"
    }
   ]
  },
  "suport_inl": {
   "types": [
    "aws_iam_group_policy"
   ],
   "where": [
    {
     "path": [
      "group"
     ],
     "op": "eq",
     "value": "SuportGroup"
    },
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "SuportPolicy"
    }
   ]
  },
  "suport_inl_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_iam_group_policy"
    },
    {
     "path": [
      "properties",
      "name"
     ],
     "op": "eq",
     "value": "SuportPolicy"
    }
   ]
  },
  "admin_patt": {
   "types": [
    "aws_iam_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "groups",
      "*"
     ],
     "op": "eq",
     "value": "AdminGroup"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "billing_group",
   "kind": "exists",
   "select": "billing_g",
   "tier": "core",
   "quote": "\"BillingGroup\""
  },
  {
   "id": "billing_user",
   "kind": "exists",
   "select": "billing_u",
   "tier": "core",
   "quote": "\"Billing\""
  },
  {
   "id": "billing_member",
   "kind": "any_of",
   "tier": "core",
   "quote": "a member of that group",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "Billing"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "BillingGroup"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "BillingGroup"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "Billing"
     }
    }
   ]
  },
  {
   "id": "billing_login",
   "kind": "exists",
   "select": "billing_lp",
   "tier": "core",
   "quote": "has a console login profile"
  },
  {
   "id": "billing_pw8",
   "kind": "attr",
   "select": "billing_lp",
   "tier": "detail",
   "quote": "an 8-character generated password",
   "cond": {
    "path": [
     "password_length"
    ],
    "op": "eq",
    "value": 8
   }
  },
  {
   "id": "billing_out",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The generated passwords should be exposed as sensitive outputs alongside each username",
   "checks": [
    {
     "kind": "ref",
     "from": "outputs",
     "to": "billing_lp"
    },
    {
     "kind": "ref",
     "from": "outputs",
     "to": "billing_u"
    }
   ]
  },
  {
   "id": "admin_group",
   "kind": "exists",
   "select": "admin_g",
   "tier": "core",
   "quote": "\"AdminGroup\""
  },
  {
   "id": "admin_user",
   "kind": "exists",
   "select": "admin_u",
   "tier": "core",
   "quote": "\"Admin\""
  },
  {
   "id": "admin_member",
   "kind": "any_of",
   "tier": "core",
   "quote": "a member of that group",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "Admin"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "AdminGroup"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "AdminGroup"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "Admin"
     }
    }
   ]
  },
  {
   "id": "admin_login",
   "kind": "exists",
   "select": "admin_lp",
   "tier": "core",
   "quote": "has a console login profile"
  },
  {
   "id": "admin_pw8",
   "kind": "attr",
   "select": "admin_lp",
   "tier": "detail",
   "quote": "an 8-character generated password",
   "cond": {
    "path": [
     "password_length"
    ],
    "op": "eq",
    "value": 8
   }
  },
  {
   "id": "admin_out",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The generated passwords should be exposed as sensitive outputs alongside each username",
   "checks": [
    {
     "kind": "ref",
     "from": "outputs",
     "to": "admin_lp"
    },
    {
     "kind": "ref",
     "from": "outputs",
     "to": "admin_u"
    }
   ]
  },
  {
   "id": "suport_group",
   "kind": "exists",
   "select": "suport_g",
   "tier": "core",
   "quote": "\"SuportGroup\""
  },
  {
   "id": "suport_user",
   "kind": "exists",
   "select": "suport_u",
   "tier": "core",
   "quote": "\"Suport\""
  },
  {
   "id": "suport_member",
   "kind": "any_of",
   "tier": "core",
   "quote": "a member of that group",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "user"
        ],
        "op": "eq",
        "value": "Suport"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "SuportGroup"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_membership"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "SuportGroup"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "Suport"
     }
    }
   ]
  },
  {
   "id": "suport_login",
   "kind": "exists",
   "select": "suport_lp",
   "tier": "core",
   "quote": "has a console login profile"
  },
  {
   "id": "suport_pw8",
   "kind": "attr",
   "select": "suport_lp",
   "tier": "detail",
   "quote": "an 8-character generated password",
   "cond": {
    "path": [
     "password_length"
    ],
    "op": "eq",
    "value": 8
   }
  },
  {
   "id": "suport_out",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The generated passwords should be exposed as sensitive outputs alongside each username",
   "checks": [
    {
     "kind": "ref",
     "from": "outputs",
     "to": "suport_lp"
    },
    {
     "kind": "ref",
     "from": "outputs",
     "to": "suport_u"
    }
   ]
  },
  {
   "id": "billing_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "a custom policy named \"BillingPolicy\"",
   "checks": [
    {
     "kind": "exists",
     "select": "billing_pol"
    },
    {
     "kind": "exists",
     "select": "billing_inl"
    }
   ]
  },
  {
   "id": "billing_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "the billing group should get a custom policy named \"BillingPolicy\"",
   "checks": [
    {
     "kind": "ref",
     "from": "billing_att",
     "to": "billing_pol"
    },
    {
     "kind": "exists",
     "select": "billing_inl"
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
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "BillingGroup"
       }
      ]
     },
     "to": "billing_pol"
    }
   ]
  },
  {
   "id": "suport_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "a custom policy named \"SuportPolicy\"",
   "checks": [
    {
     "kind": "exists",
     "select": "suport_pol"
    },
    {
     "kind": "exists",
     "select": "suport_inl"
    }
   ]
  },
  {
   "id": "suport_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "the support group should get a custom policy named \"SuportPolicy\"",
   "checks": [
    {
     "kind": "ref",
     "from": "suport_att",
     "to": "suport_pol"
    },
    {
     "kind": "exists",
     "select": "suport_inl"
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
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "SuportGroup"
       }
      ]
     },
     "to": "suport_pol"
    }
   ]
  },
  {
   "id": "admin_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "the AWS-managed AdministratorAccess policy",
   "checks": [
    {
     "kind": "attr",
     "select": "admin_att",
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "policy/AdministratorAccess$"
     }
    },
    {
     "kind": "attr",
     "select": "admin_patt",
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "policy/AdministratorAccess$"
     }
    },
    {
     "kind": "ref",
     "from": "admin_att",
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "AdministratorAccess"
       }
      ]
     }
    }
   ]
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "billing_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_pol",
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
        "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_inl",
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
        "value": "(?i)(aws-portal|awsbillingconsole|billing):(View|Get)"
       }
      ]
     }
    }
   ],
   "id": "billing_billing",
   "tier": "core",
   "quote": "read-only billing, usage, budget, cost report, and pricing visibility"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "billing_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
     }
    },
    {
     "kind": "attr",
     "select": "billing_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
     }
    },
    {
     "kind": "ref",
     "from": "billing_pol",
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
        "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
     }
    },
    {
     "kind": "ref",
     "from": "billing_inl",
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
        "value": "(?i)((aws-portal|awsbillingconsole):(ViewUsage|View\\*)|ce:(Get))"
       }
      ]
     }
    }
   ],
   "id": "billing_usage",
   "tier": "core",
   "quote": "read-only billing, usage, budget, cost report, and pricing visibility"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "billing_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)budgets:(View|Describe|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)budgets:(View|Describe|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_pol",
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
        "value": "(?i)budgets:(View|Describe|Get)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)budgets:(View|Describe|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)budgets:(View|Describe|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_inl",
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
        "value": "(?i)budgets:(View|Describe|Get)"
       }
      ]
     }
    }
   ],
   "id": "billing_budget",
   "tier": "core",
   "quote": "read-only billing, usage, budget, cost report, and pricing visibility"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "billing_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
     }
    },
    {
     "kind": "attr",
     "select": "billing_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
     }
    },
    {
     "kind": "ref",
     "from": "billing_pol",
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
        "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
     }
    },
    {
     "kind": "ref",
     "from": "billing_inl",
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
        "value": "(?i)(cur:(Describe|Get)|ce:(DescribeReport|Get|Describe))"
       }
      ]
     }
    }
   ],
   "id": "billing_cur",
   "tier": "core",
   "quote": "read-only billing, usage, budget, cost report, and pricing visibility",
   "justify": "a cost report is readable through Cost Explorer reports (ce:DescribeReport) as well as the cost and usage report API (cur:)"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "billing_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)pricing:(Describe|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)pricing:(Describe|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_pol",
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
        "value": "(?i)pricing:(Describe|Get)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)pricing:(Describe|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "billing_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)pricing:(Describe|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "billing_inl",
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
        "value": "(?i)pricing:(Describe|Get)"
       }
      ]
     }
    }
   ],
   "id": "billing_pricing",
   "tier": "core",
   "quote": "read-only billing, usage, budget, cost report, and pricing visibility"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "suport_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(Describe|Get|List)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(Describe|Get|List)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_pol",
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
        "value": "(?i)ec2:(Describe|Get|List)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(Describe|Get|List)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(Describe|Get|List)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_inl",
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
        "value": "(?i)ec2:(Describe|Get|List)"
       }
      ]
     }
    }
   ],
   "id": "suport_ec2",
   "tier": "core",
   "quote": "read-only describe, get, and list access to EC2, S3, CloudWatch, and RDS"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "suport_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(Get|List|Describe)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(Get|List|Describe)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_pol",
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
        "value": "(?i)s3:(Get|List|Describe)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(Get|List|Describe)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(Get|List|Describe)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_inl",
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
        "value": "(?i)s3:(Get|List|Describe)"
       }
      ]
     }
    }
   ],
   "id": "suport_s3",
   "tier": "core",
   "quote": "read-only describe, get, and list access to EC2, S3, CloudWatch, and RDS"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "suport_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(Describe|Get|List)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(Describe|Get|List)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_pol",
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
        "value": "(?i)cloudwatch:(Describe|Get|List)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(Describe|Get|List)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(Describe|Get|List)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_inl",
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
        "value": "(?i)cloudwatch:(Describe|Get|List)"
       }
      ]
     }
    }
   ],
   "id": "suport_cloudwatch",
   "tier": "core",
   "quote": "read-only describe, get, and list access to EC2, S3, CloudWatch, and RDS"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "suport_pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)rds:(Describe|List|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_pol_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)rds:(Describe|List|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_pol",
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
        "value": "(?i)rds:(Describe|List|Get)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)rds:(Describe|List|Get)"
     }
    },
    {
     "kind": "attr",
     "select": "suport_inl_decl",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)rds:(Describe|List|Get)"
     }
    },
    {
     "kind": "ref",
     "from": "suport_inl",
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
        "value": "(?i)rds:(Describe|List|Get)"
       }
      ]
     }
    }
   ],
   "id": "suport_rds",
   "tier": "core",
   "quote": "read-only describe, get, and list access to EC2, S3, CloudWatch, and RDS"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
