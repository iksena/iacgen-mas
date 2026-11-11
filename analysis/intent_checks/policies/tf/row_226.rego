package intent.tf.row_226

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
  },
  "pol": {
   "types": [
    "aws_iam_policy",
    "aws_iam_role_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "an IAM role and instance profile for an EC2 Packer builder instance"
  },
  {
   "id": "role_ec2_trust",
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
      "value": "ec2\\.amazonaws\\.com"
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
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "ec2\\.amazonaws\\.com"
     }
    }
   ],
   "tier": "core",
   "quote": "for an EC2 Packer builder instance",
   "justify": "an EC2 instance role is assumed by the EC2 service principal"
  },
  {
   "id": "profile",
   "kind": "exists",
   "select": "prof",
   "tier": "core",
   "quote": "an IAM role and instance profile"
  },
  {
   "id": "profile_role",
   "kind": "ref",
   "from": "prof",
   "to": "role",
   "tier": "core",
   "quote": "an IAM role and instance profile"
  },
  {
   "id": "policy",
   "kind": "exists",
   "select": "pol",
   "tier": "core",
   "quote": "a policy allowing it to assume a role in another account"
  },
  {
   "id": "policy_assume",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)sts:(AssumeRole|\\*)([^A-Za-z0-9_]|$)"
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
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)sts:(AssumeRole|\\*)([^A-Za-z0-9_]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "a policy allowing it to assume a role in another account"
  },
  {
   "id": "policy_attached",
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
     "to": "role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "role"
    }
   ],
   "tier": "detail",
   "quote": "with a policy allowing it to assume a role in another account"
  },
  {
   "id": "policy_role_arn",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "arn:aws:iam::.*:role/"
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
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "arn:aws:iam::.*:role/"
     }
    }
   ],
   "tier": "detail",
   "quote": "to read software installation files from S3, using an environment-specific resource name prefix and a target account ID and role name"
  },
  {
   "id": "param_account",
   "kind": "exists",
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
      "value": "(?i)account"
     }
    ]
   },
   "tier": "detail",
   "quote": "a target account ID and role name"
  },
  {
   "id": "target_role_configurable",
   "kind": "any_of",
   "checks": [
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
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": ":role/\\$\\{(var|local)\\."
     }
    },
    {
     "kind": "exists",
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
        "value": "(?i)role"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "a target account ID and role name"
  },
  {
   "id": "param_env",
   "kind": "exists",
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
      "value": "(?i)(environment|prefix)"
     }
    ]
   },
   "tier": "detail",
   "quote": "an environment-specific resource name prefix"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
