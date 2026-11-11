package intent.tf.row_342

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "r1": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-role"
    }
   ]
  },
  "r2": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-role2"
    }
   ]
  },
  "p1": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-policy"
    }
   ]
  },
  "p2": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-policy2"
    }
   ]
  },
  "p3": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-policy3"
    }
   ]
  },
  "att5": {
   "types": [
    "aws_iam_policy_attachment"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "test-attachment5"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role1",
   "kind": "exists",
   "tier": "core",
   "select": "r1",
   "quote": "two IAM roles for testing, \"test-role\" and \"test-role2\""
  },
  {
   "id": "role2",
   "kind": "exists",
   "tier": "core",
   "select": "r2",
   "quote": "two IAM roles for testing, \"test-role\" and \"test-role2\""
  },
  {
   "id": "role1_ec2",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "r1",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)ec2\\.amazonaws\\.com"
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
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "test-role"
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
   ],
   "quote": "both assumable by EC2"
  },
  {
   "id": "role2_ec2",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "r2",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)ec2\\.amazonaws\\.com"
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
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "test-role2"
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
   ],
   "quote": "both assumable by EC2"
  },
  {
   "id": "policy1",
   "kind": "exists",
   "tier": "core",
   "select": "p1",
   "quote": "three customer-managed IAM policies named \"test-policy\", \"test-policy2\", and \"test-policy3\""
  },
  {
   "id": "policy2",
   "kind": "exists",
   "tier": "core",
   "select": "p2",
   "quote": "three customer-managed IAM policies named \"test-policy\", \"test-policy2\", and \"test-policy3\""
  },
  {
   "id": "policy3",
   "kind": "exists",
   "tier": "core",
   "select": "p3",
   "quote": "three customer-managed IAM policies named \"test-policy\", \"test-policy2\", and \"test-policy3\""
  },
  {
   "id": "policy1_describe",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "p1",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
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
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "test-policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
     }
    }
   ],
   "quote": "each allow only EC2 describe actions",
   "justify": "policy text whose only actions are ec2:Describe* (Resource may be \"*\")"
  },
  {
   "id": "policy2_describe",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "p2",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
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
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "test-policy2"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
     }
    }
   ],
   "quote": "each allow only EC2 describe actions",
   "justify": "policy text whose only actions are ec2:Describe* (Resource may be \"*\")"
  },
  {
   "id": "policy3_describe",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "p3",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
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
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "test-policy3"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)^(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"'])*ec2:describe[a-z0-9*]*(?:[^a-z0-9_*:.-]|[\"']\\s*:|[a-z0-9_.-]+|resources?[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|ec2:describe[a-z0-9*]*)*$"
     }
    }
   ],
   "quote": "each allow only EC2 describe actions",
   "justify": "policy text whose only actions are ec2:Describe* (Resource may be \"*\")"
  },
  {
   "id": "attach_r1_p1",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach the first two policies to both roles individually",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "test-role"
       }
      ]
     },
     "to": "p1"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachments_exclusive"
      ],
      "where": [
       {
        "path": [
         "role_name"
        ],
        "op": "eq",
        "value": "test-role"
       }
      ]
     },
     "to": "p1"
    }
   ]
  },
  {
   "id": "attach_r1_p2",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach the first two policies to both roles individually",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "test-role"
       }
      ]
     },
     "to": "p2"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachments_exclusive"
      ],
      "where": [
       {
        "path": [
         "role_name"
        ],
        "op": "eq",
        "value": "test-role"
       }
      ]
     },
     "to": "p2"
    }
   ]
  },
  {
   "id": "attach_r2_p1",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach the first two policies to both roles individually",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "test-role2"
       }
      ]
     },
     "to": "p1"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachments_exclusive"
      ],
      "where": [
       {
        "path": [
         "role_name"
        ],
        "op": "eq",
        "value": "test-role2"
       }
      ]
     },
     "to": "p1"
    }
   ]
  },
  {
   "id": "attach_r2_p2",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach the first two policies to both roles individually",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "test-role2"
       }
      ]
     },
     "to": "p2"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachments_exclusive"
      ],
      "where": [
       {
        "path": [
         "role_name"
        ],
        "op": "eq",
        "value": "test-role2"
       }
      ]
     },
     "to": "p2"
    }
   ]
  },
  {
   "id": "att5_exists",
   "kind": "exists",
   "tier": "core",
   "select": "att5",
   "quote": "attach \"test-policy3\" to both roles through a single named policy attachment called \"test-attachment5\""
  },
  {
   "id": "att5_p3",
   "kind": "ref",
   "tier": "core",
   "from": "att5",
   "to": "p3",
   "quote": "attach \"test-policy3\" to both roles through a single named policy attachment called \"test-attachment5\""
  },
  {
   "id": "att5_r1",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach \"test-policy3\" to both roles through a single named policy attachment called \"test-attachment5\"",
   "checks": [
    {
     "kind": "ref",
     "from": "att5",
     "to": "r1"
    },
    {
     "kind": "attr",
     "select": "att5",
     "cond": {
      "path": [
       "roles",
       "*"
      ],
      "op": "eq",
      "value": "test-role"
     }
    }
   ]
  },
  {
   "id": "att5_r2",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach \"test-policy3\" to both roles through a single named policy attachment called \"test-attachment5\"",
   "checks": [
    {
     "kind": "ref",
     "from": "att5",
     "to": "r2"
    },
    {
     "kind": "attr",
     "select": "att5",
     "cond": {
      "path": [
       "roles",
       "*"
      ],
      "op": "eq",
      "value": "test-role2"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
