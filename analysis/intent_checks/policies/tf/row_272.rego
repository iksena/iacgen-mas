package intent.tf.row_272

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "devel_group": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Ersia_Devel_Group"
    }
   ]
  },
  "guest_group": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Ersia_Guest_Group"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "devel_group",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "Ersia_Devel_Group"
   },
   "quote": "\"Ersia_Devel_Group\""
  },
  {
   "id": "guest_group",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "Ersia_Guest_Group"
   },
   "quote": "\"Ersia_Guest_Group\""
  },
  {
   "id": "devel_readonly",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "Ersia_Devel_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)ReadOnlyAccess$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)(^|/)ReadOnlyAccess$"
       }
      ]
     },
     "to": "devel_group"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "Ersia_Devel_Group"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ReadOnlyAccess"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
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
        "value": "Ersia_Devel_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)ReadOnlyAccess$"
     }
    }
   ],
   "quote": "\"Ersia_Devel_Group\" with the AWS-managed ReadOnlyAccess policy"
  },
  {
   "id": "guest_iamreadonly",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "Ersia_Guest_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)IAMReadOnlyAccess$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)(^|/)IAMReadOnlyAccess$"
       }
      ]
     },
     "to": "guest_group"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "Ersia_Guest_Group"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "IAMReadOnlyAccess"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
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
        "value": "Ersia_Guest_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)IAMReadOnlyAccess$"
     }
    }
   ],
   "quote": "\"Ersia_Guest_Group\" with the AWS-managed IAMReadOnlyAccess policy"
  },
  {
   "id": "user_dev1",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "dev1"
   },
   "quote": "IAM users \"dev1\" and \"dev2\""
  },
  {
   "id": "user_dev2",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "dev2"
   },
   "quote": "IAM users \"dev1\" and \"dev2\""
  },
  {
   "id": "user_guest",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "guest"
   },
   "quote": "and \"guest\" tagged with Owner \"Guest\""
  },
  {
   "id": "dev1_tag",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "dev1"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Owner"
      ],
      "op": "eq",
      "value": "Devel"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "dev1"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Owner"
      ],
      "op": "eq",
      "value": "Devel"
     }
    }
   ],
   "quote": "\"dev1\" and \"dev2\" tagged with Owner \"Devel\""
  },
  {
   "id": "dev2_tag",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "dev2"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Owner"
      ],
      "op": "eq",
      "value": "Devel"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "dev2"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Owner"
      ],
      "op": "eq",
      "value": "Devel"
     }
    }
   ],
   "quote": "\"dev1\" and \"dev2\" tagged with Owner \"Devel\""
  },
  {
   "id": "guest_tag",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "guest"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Owner"
      ],
      "op": "eq",
      "value": "Guest"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "guest"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Owner"
      ],
      "op": "eq",
      "value": "Guest"
     }
    }
   ],
   "quote": "\"guest\" tagged with Owner \"Guest\""
  },
  {
   "id": "configurable_map",
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
      "op": "contains",
      "value": "dev1"
     },
     {
      "path": [
       "default"
      ],
      "op": "contains",
      "value": "guest"
     }
    ]
   },
   "quote": "defined through a configurable map"
  },
  {
   "id": "dev1_in_devel",
   "tier": "core",
   "kind": "any_of",
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
        "value": "dev1"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "Ersia_Devel_Group"
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
        "value": "Ersia_Devel_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "dev1"
     }
    }
   ],
   "quote": "Each user must join the developer group when its Owner tag is \"Devel\""
  },
  {
   "id": "dev2_in_devel",
   "tier": "core",
   "kind": "any_of",
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
        "value": "dev2"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "Ersia_Devel_Group"
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
        "value": "Ersia_Devel_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "dev2"
     }
    }
   ],
   "quote": "Each user must join the developer group when its Owner tag is \"Devel\""
  },
  {
   "id": "guest_in_guest",
   "tier": "core",
   "kind": "any_of",
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
        "value": "guest"
       }
      ]
     },
     "cond": {
      "path": [
       "groups",
       "*"
      ],
      "op": "eq",
      "value": "Ersia_Guest_Group"
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
        "value": "Ersia_Guest_Group"
       }
      ]
     },
     "cond": {
      "path": [
       "users",
       "*"
      ],
      "op": "eq",
      "value": "guest"
     }
    }
   ],
   "quote": "the guest group otherwise"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
