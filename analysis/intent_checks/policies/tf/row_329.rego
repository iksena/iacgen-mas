package intent.tf.row_329

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
     "value": "ec2-ssm-association"
    }
   ]
  },
  "attach": {
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
     "value": "/AmazonSSMManagedInstanceCore$"
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
     "value": "ec2-s3-ssm-association"
    }
   ]
  },
  "any_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "any_profile": {
   "types": [
    "aws_iam_instance_profile"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role_named",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role named \"ec2-ssm-association\"",
   "select": "role"
  },
  {
   "id": "ec2_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "that EC2 instances can assume",
   "checks": [
    {
     "kind": "attr",
     "select": "any_role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": "any_role",
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
   ]
  },
  {
   "id": "ssm_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "with the AWS-managed AmazonSSMManagedInstanceCore policy attached",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": "any_role"
    },
    {
     "kind": "join",
     "from": "attach",
     "from_path": [
      "role"
     ],
     "to": "any_role",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "attr",
     "select": "any_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "/AmazonSSMManagedInstanceCore$"
     }
    }
   ]
  },
  {
   "id": "profile_named",
   "kind": "exists",
   "tier": "core",
   "quote": "an instance profile named \"ec2-s3-ssm-association\"",
   "select": "profile"
  },
  {
   "id": "profile_has_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "for that role",
   "checks": [
    {
     "kind": "ref",
     "from": "any_profile",
     "to": "any_role"
    },
    {
     "kind": "join",
     "from": "any_profile",
     "from_path": [
      "role"
     ],
     "to": "any_role",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "join",
     "from": "any_profile",
     "from_path": [
      "roles",
      "*"
     ],
     "to": "any_role",
     "to_path": [
      "name"
     ]
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
