package intent.tf.row_045

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pol": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "powerscale-node-runtime-policy$"
    }
   ]
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "powerscale-node-runtime-role$"
    }
   ]
  },
  "prof": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "powerscale-node-runtime-instance-profile$"
    }
   ]
  },
  "polstr": {
   "types": [
    "aws_iam_policy",
    "data.aws_iam_policy_document",
    "aws_iam_role_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "policy_named",
   "tier": "core",
   "quote": "an IAM policy named \"<account_id>-powerscale-node-runtime-policy\"",
   "kind": "exists",
   "select": "pol"
  },
  {
   "id": "role_named",
   "tier": "core",
   "quote": "an IAM role named \"<account_id>-powerscale-node-runtime-role\"",
   "kind": "exists",
   "select": "role"
  },
  {
   "id": "profile_named",
   "tier": "core",
   "quote": "an IAM instance profile named \"<account_id>-powerscale-node-runtime-instance-profile\"",
   "kind": "exists",
   "select": "prof"
  },
  {
   "id": "account_prefix",
   "tier": "detail",
   "quote": "dynamically prefix resource names with the current AWS account ID",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role",
       "aws_iam_instance_profile"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "powerscale-node-runtime"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^[0-9]{12}-"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role",
       "aws_iam_instance_profile"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "powerscale-node-runtime"
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
    }
   ],
   "justify": "an AWS account ID is 12 digits"
  },
  {
   "id": "policy_assign_ip",
   "tier": "core",
   "quote": "allow the \"ec2:AssignPrivateIpAddresses\" action",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:AssignPrivateIpAddresses"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*",
       "actions",
       "*"
      ],
      "op": "glob_covers",
      "value": "ec2:AssignPrivateIpAddresses"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:AssignPrivateIpAddresses"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_network_interface",
   "tier": "detail",
   "quote": "targeted at network interface resources",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "network-interface"
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "network-interface"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "regions_var_default_star",
   "tier": "detail",
   "quote": "configurable list of AWS regions, which should default to a list containing \"*\"",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default",
       "*"
      ],
      "op": "eq",
      "value": "*"
     }
    ]
   }
  },
  {
   "id": "role_trust_ec2",
   "tier": "core",
   "quote": "allow the EC2 service principal (\"ec2.amazonaws.com\") to assume it",
   "kind": "any_of",
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
      "value": "ec2\\.amazonaws\\.com"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
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
        "op": "in",
        "value": [
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ec2\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_attached_to_role",
   "tier": "core",
   "quote": "the IAM role must allow the EC2 service principal (\"ec2.amazonaws.com\") to assume it and have the custom IAM policy explicitly attached to it",
   "kind": "any_of",
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
        "op": "regex",
        "value": "powerscale-node-runtime-role$"
       }
      ]
     },
     "to": "pol"
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
         "roles",
         "*"
        ],
        "op": "regex",
        "value": "powerscale-node-runtime-role$"
       }
      ]
     },
     "to": "pol"
    },
    {
     "kind": "ref",
     "from": "role",
     "to": "pol"
    }
   ]
  },
  {
   "id": "instance_profile_uses_role",
   "tier": "detail",
   "quote": "an IAM instance profile",
   "kind": "ref",
   "from": "prof",
   "to": "role"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
