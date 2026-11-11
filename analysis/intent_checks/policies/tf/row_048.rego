package intent.tf.row_048

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "prof": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "tier": "core",
   "quote": "creates an IAM role and instance profile for EC2 instances",
   "kind": "exists",
   "select": "role"
  },
  {
   "id": "instance_profile",
   "tier": "core",
   "quote": "creates an IAM role and instance profile for EC2 instances",
   "kind": "exists",
   "select": "prof"
  },
  {
   "id": "profile_uses_role",
   "tier": "core",
   "quote": "IAM role and instance profile",
   "kind": "ref",
   "from": "prof",
   "to": "role"
  },
  {
   "id": "trust_ec2",
   "tier": "core",
   "quote": "grants the correct partition-specific EC2 service principal permission to assume the role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
      "op": "regex",
      "value": "(?i)^ec2\\."
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
        "value": "(?i)ec2\\.(amazonaws\\.com|\\$\\{)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "trust_assume_action",
   "tier": "detail",
   "quote": "permission to assume the role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)sts:AssumeRole"
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
      "value": "sts:AssumeRole"
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
        "value": "(?i)sts:AssumeRole"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "trust_partition_aware",
   "tier": "detail",
   "quote": "automatically grants the correct partition-specific EC2 service principal",
   "kind": "any_of",
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2"
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
        "value": "data.aws_partition"
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
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2"
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
        "value": "data.aws_service_principal"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "inline_policies_supported",
   "tier": "core",
   "quote": "support for attaching a configurable set of inline and managed IAM policies",
   "kind": "any_of",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "aws_iam_role_policies_exclusive"
        ]
       }
      ]
     },
     "to": "role"
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
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "inline_policy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "managed_policies_supported",
   "tier": "core",
   "quote": "support for attaching a configurable set of inline and managed IAM policies",
   "kind": "any_of",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment",
         "aws_iam_role_policy_attachments_exclusive"
        ]
       }
      ]
     },
     "to": "role"
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
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "managed_policy_arns"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policies_configurable",
   "tier": "detail",
   "quote": "a configurable set of inline and managed IAM policies",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
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
        "op": "in",
        "value": [
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(inline_policy|managed_policy_arns)"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
