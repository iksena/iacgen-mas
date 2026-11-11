package intent.tf.row_011

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "role_named",
   "kind": "exists",
   "tier": "core",
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
      "value": "role"
     }
    ]
   },
   "quote": "creates an IAM role named \"role\""
  },
  {
   "id": "role_assumed_by_ec2",
   "kind": "any_of",
   "tier": "core",
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
        "value": "role"
       }
      ]
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?s)\"Action\":\\[?(\"[^\"]*\",)*\"sts:(AssumeRole|\\*)\"(,\"[^\"]*\")*\\]?,(?:\"Condition\":\\{(?:[^{}]|\\{[^{}]*\\})*\\},)?\"Effect\":\"Allow\",\"Principal\":\\{(?:\"AWS\":(?:\"[^\"]*\"|\\[[^\\]]*\\]),)?\"Service\":\\[?(\"[^\"]*\",)*\"ec2\\.amazonaws\\.com\""
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
        "value": "role"
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
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sts:AssumeRole"
         },
         {
          "path": [
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
        "value": "role"
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
   "quote": "can be assumed by the EC2 service"
  },
  {
   "id": "policy1_named",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
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
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "allow-policy-1"
     }
    }
   ],
   "quote": "\"allow-policy-1\"",
   "justify": "exact policy name stated in the prompt"
  },
  {
   "id": "policy1_passrole",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(passrole|\\*)"
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
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(passrole|\\*)"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)iam:(passrole|\\*)"
     }
    }
   ],
   "quote": "allows passing IAM roles"
  },
  {
   "id": "policy1_resources",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
     }
    }
   ],
   "quote": "across all resources"
  },
  {
   "id": "policy2_named",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
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
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "allow-policy-2"
     }
    }
   ],
   "quote": "\"allow-policy-2\"",
   "justify": "exact policy name stated in the prompt"
  },
  {
   "id": "policy2_create_function",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(createfunction|create\\*|\\*)"
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
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)lambda:(createfunction|create\\*|\\*)"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(createfunction|create\\*|\\*)"
     }
    }
   ],
   "quote": "allows creating Lambda functions"
  },
  {
   "id": "policy2_invoke",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(invokefunc\\*|invoke\\*|\\*)"
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
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)lambda:(invokefunc\\*|invoke\\*|\\*)"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)lambda:(invokefunc\\*|invoke\\*|\\*)"
     }
    }
   ],
   "quote": "invoking Lambda functions matching the \"lambda:invokefunc*\" pattern"
  },
  {
   "id": "policy2_resources",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)[\"']resource[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']"
     }
    }
   ],
   "quote": "on all resources"
  },
  {
   "id": "policy1_on_role",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
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
        "value": "role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "inline_policy",
         "*",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-1"
       }
      ]
     }
    }
   ],
   "quote": "Attached to this role, configure two inline policies"
  },
  {
   "id": "policy2_on_role",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
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
        "value": "role"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "inline_policy",
         "*",
         "name"
        ],
        "op": "eq",
        "value": "allow-policy-2"
       }
      ]
     }
    }
   ],
   "quote": "Attached to this role, configure two inline policies"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
