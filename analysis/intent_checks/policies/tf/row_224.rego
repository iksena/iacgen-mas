package intent.tf.row_224

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
   "quote": "creates an IAM role and instance profile for an EC2 instance",
   "select": "role"
  },
  {
   "id": "role_trust_ec2",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM role allowing assume role permissions for EC2 services",
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
   "id": "role_name_default",
   "kind": "attr",
   "tier": "core",
   "quote": "a default name of \"tamr-instance-role\"",
   "select": "role",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "tamr-instance-role"
   }
  },
  {
   "id": "permissions_boundary_optional",
   "kind": "exists",
   "tier": "detail",
   "quote": "an optional permissions boundary",
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
       "permissions_boundary"
      ],
      "op": "regex",
      "value": "\\$\\{"
     }
    ]
   }
  },
  {
   "id": "profile",
   "kind": "exists",
   "tier": "core",
   "quote": "an associated IAM instance profile",
   "select": "profile"
  },
  {
   "id": "profile_uses_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "an associated IAM instance profile",
   "checks": [
    {
     "kind": "ref",
     "from": "profile",
     "to": "role"
    },
    {
     "kind": "join",
     "from": "profile",
     "from_path": [
      "role"
     ],
     "to": "role",
     "to_path": [
      "name"
     ]
    }
   ]
  },
  {
   "id": "profile_name_default",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to \"tamr-instance-profile\"",
   "select": "profile",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "tamr-instance-profile"
   }
  },
  {
   "id": "tags_map",
   "kind": "any_of",
   "tier": "detail",
   "quote": "supporting a customizable map of resource tags",
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
         "aws_iam_role",
         "aws_iam_instance_profile"
        ]
       },
       {
        "path": [
         "properties",
         "tags"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "tags"
      ],
      "op": "present"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
