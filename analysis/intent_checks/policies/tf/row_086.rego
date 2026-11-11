package intent.tf.row_086

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "group_developers",
   "tier": "core",
   "quote": "an IAM group named \"developers\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "developers"
     }
    ]
   }
  },
  {
   "id": "users_default",
   "tier": "core",
   "quote": "a list of default users including \"jack\" and \"jones\"",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
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
        "value": "jack"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "jones"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "users_tag",
   "tier": "detail",
   "quote": "tagged with \"user_created_by\" set to \"terraform\"",
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
        "op": "in",
        "value": [
         "jack",
         "jones"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "user_created_by"
      ],
      "op": "eq",
      "value": "terraform"
     },
     "quantifier": "all"
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
        "op": "in",
        "value": [
         "jack",
         "jones"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "user_created_by"
      ],
      "op": "eq",
      "value": "terraform"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "rw_policy_name",
   "tier": "core",
   "quote": "an IAM policy named \"iam_read_only_and_s3_full_access\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "iam_read_only_and_s3_full_access"
     }
    ]
   }
  },
  {
   "id": "rw_policy_iam_read",
   "tier": "detail",
   "quote": "containing default statements for IAM read actions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(get|list|\\*)"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(get|list|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)iam:(get|list|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rw_policy_s3_read",
   "tier": "detail",
   "quote": "S3 object read/write access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(get\\*|getobject|\\*)"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(get\\*|getobject|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)s3:(get\\*|getobject|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rw_policy_s3_write",
   "tier": "detail",
   "quote": "S3 object read/write access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(put\\*|putobject|\\*)"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(put\\*|putobject|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)s3:(put\\*|putobject|\\*)"
       }
      ]
     }
    }
   ],
   "justify": "read/write access implies a put action"
  },
  {
   "id": "rw_policy_attached_group",
   "tier": "core",
   "quote": "attached to the group",
   "kind": "any_of",
   "checks": [
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
        "value": "developers"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     }
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
        "value": "developers"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "iam_read_only_and_s3_full_access"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "screenshot_policy_name",
   "tier": "core",
   "quote": "an IAM policy named \"ec2_get_console_screenshot\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "ec2_get_console_screenshot"
     }
    ]
   }
  },
  {
   "id": "screenshot_policy_action",
   "tier": "detail",
   "quote": "granting EC2 console screenshot permissions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2_get_console_screenshot"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(getconsolescreenshot|get\\*|\\*)"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "ec2_get_console_screenshot"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:(getconsolescreenshot|get\\*|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2_get_console_screenshot"
       }
      ]
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)ec2:(getconsolescreenshot|get\\*|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "screenshot_attached_users",
   "tier": "core",
   "quote": "attached directly to each created user",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2_get_console_screenshot"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "ec2_get_console_screenshot"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "screenshot_attached_each",
   "tier": "detail",
   "quote": "attached directly to each created user",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "distinct_path": [
      "user"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "users"
        ],
        "op": "len_gte",
        "value": 2
       }
      ]
     }
    }
   ],
   "justify": "two default users jack and jones each get an attachment"
  },
  {
   "id": "membership_developers",
   "tier": "core",
   "quote": "user membership in the developers group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user_group_membership"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "developers"
       }
      ]
     },
     "min": 2,
     "distinct_path": [
      "user"
     ]
    },
    {
     "kind": "exists",
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
        "value": "developers"
       },
       {
        "path": [
         "users"
        ],
        "op": "len_gte",
        "value": 2
       }
      ]
     }
    }
   ],
   "justify": "two default users jack and jones are each members"
  },
  {
   "id": "role_instance_role",
   "tier": "core",
   "quote": "an EC2 assume role named \"instance_role\"",
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
      "value": "instance_role"
     }
    ]
   }
  },
  {
   "id": "role_assumed_by_ec2",
   "tier": "core",
   "quote": "an EC2 assume role named \"instance_role\"",
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
        "value": "instance_role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)ec2\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "instance_role"
       }
      ]
     },
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
        "value": "ec2.amazonaws.com"
       }
      ]
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
        "value": "instance_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)ec2\\.amazonaws\\.com"
     }
    }
   ]
  },
  {
   "id": "role_readonly_policy",
   "tier": "core",
   "quote": "attached to the AWS-managed \"IAMReadOnlyAccess\" policy ARN",
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
        "value": "instance_role"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "policy/IAMReadOnlyAccess$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/IAMReadOnlyAccess$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "instance_role"
       }
      ]
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
        "value": "instance_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "IAMReadOnlyAccess"
     }
    }
   ]
  },
  {
   "id": "toggles",
   "tier": "detail",
   "quote": "independent boolean creation toggles for an IAM developer group, an IAM read-only and S3 read/write access policy, the group policy attachment, IAM users, an EC2 console screenshot policy, the user policy attachments, group membership associations, and an EC2 instance role",
   "kind": "all_of",
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
        "op": "eq",
        "value": "aws_iam_group"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     },
     "min": 2
    },
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
        "op": "eq",
        "value": "aws_iam_group_policy_attachment"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "aws_iam_user"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "aws_iam_user_policy_attachment"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "justify": "eight toggles; policies are two resources of one type"
  },
  {
   "id": "toggle_membership",
   "tier": "detail",
   "quote": "independent boolean creation toggles for an IAM developer group, an IAM read-only and S3 read/write access policy, the group policy attachment, IAM users, an EC2 console screenshot policy, the user policy attachments, group membership associations, and an EC2 instance role",
   "kind": "any_of",
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
        "op": "eq",
        "value": "aws_iam_user_group_membership"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "aws_iam_group_membership"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "group_attachment_refs_group",
   "tier": "extra",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_group_policy_attachment"
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
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
