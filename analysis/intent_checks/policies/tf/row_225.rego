package intent.tf.row_225

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "AWSRDSCustomSQLServerInstanceRole"
    }
   ]
  },
  "profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "AWSRDSCustomSQLServerInstanceProfile"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_name",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role named \"AWSRDSCustomSQLServerInstanceRole\"",
   "select": "role"
  },
  {
   "id": "role_root_path",
   "kind": "attr",
   "tier": "detail",
   "quote": "at the root path",
   "select": "role",
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   }
  },
  {
   "id": "role_trust_ec2",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing EC2 assume role trust",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "role",
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
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    }
   ],
   "justify": "EC2 service principal is ec2.amazonaws.com"
  },
  {
   "id": "managed_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "attaches the AWS managed \"AmazonRDSCustomInstanceProfileRolePolicy\" policy to it",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/AmazonRDSCustomInstanceProfileRolePolicy$"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/AmazonRDSCustomInstanceProfileRolePolicy$"
       },
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSRDSCustomSQLServerInstanceRole"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "policy/AmazonRDSCustomInstanceProfileRolePolicy$"
     }
    }
   ]
  },
  {
   "id": "profile_name",
   "kind": "exists",
   "tier": "core",
   "quote": "an associated IAM instance profile named \"AWSRDSCustomSQLServerInstanceProfile\"",
   "select": "profile"
  },
  {
   "id": "profile_uses_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "provisions an associated IAM instance profile",
   "checks": [
    {
     "kind": "ref",
     "from": "profile",
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "profile",
     "cond": {
      "path": [
       "role"
      ],
      "op": "eq",
      "value": "AWSRDSCustomSQLServerInstanceRole"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
