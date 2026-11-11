package intent.tf.row_223

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
  "profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an IAM role and instance profile",
   "select": "role"
  },
  {
   "id": "profile",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an IAM role and instance profile",
   "select": "profile"
  },
  {
   "id": "profile_uses_role",
   "kind": "ref",
   "tier": "core",
   "quote": "an IAM role and instance profile for EC2 image building automation",
   "from": "profile",
   "to": "role"
  },
  {
   "id": "role_trust_ec2",
   "kind": "any_of",
   "tier": "core",
   "quote": "ensuring the role assumes trust for EC2 services",
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
   "id": "role_root_path",
   "kind": "attr",
   "tier": "detail",
   "quote": "uses a root path",
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
   "id": "imagebuilder_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "attaches the AWS-managed full access policy for Image Builder",
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
        "value": "policy/AWSImageBuilderFullAccess$"
       }
      ]
     },
     "to": "role"
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
      "value": "policy/AWSImageBuilderFullAccess$"
     }
    }
   ],
   "justify": "AWS-managed full access policy for Image Builder is AWSImageBuilderFullAccess"
  },
  {
   "id": "role_prefix",
   "kind": "any_of",
   "tier": "core",
   "quote": "applies a prefix of \"imagebuilder_\" to both the role and instance profile names",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^imagebuilder_"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^imagebuilder_"
     }
    }
   ]
  },
  {
   "id": "profile_prefix",
   "kind": "any_of",
   "tier": "core",
   "quote": "applies a prefix of \"imagebuilder_\" to both the role and instance profile names",
   "checks": [
    {
     "kind": "attr",
     "select": "profile",
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^imagebuilder_"
     }
    },
    {
     "kind": "attr",
     "select": "profile",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^imagebuilder_"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
