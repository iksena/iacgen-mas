package intent.cfn.row_243

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "prof": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "par": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "CfnBucketName"
    }
   ]
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "ec2_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "ec2.amazonaws.com"
    }
   ]
  },
  "named_inline": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "Policies",
      "*",
      "PolicyName"
     ],
     "op": "eq",
     "value": "S3Download"
    }
   ]
  },
  "named_pol": {
   "types": [
    "AWS::IAM::Policy"
   ],
   "where": [
    {
     "path": [
      "PolicyName"
     ],
     "op": "eq",
     "value": "S3Download"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "param_default",
   "kind": "attr",
   "tier": "core",
   "select": "par",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "agilefant"
   },
   "quote": "a parameter CfnBucketName defaulting to \"agilefant\""
  },
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "quote": "an IAM role"
  },
  {
   "id": "role_trust",
   "kind": "attr",
   "tier": "core",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "ec2.amazonaws.com"
   },
   "quote": "an IAM role at path \"/\" trusting \"ec2.amazonaws.com\""
  },
  {
   "id": "role_path",
   "tier": "detail",
   "quote": "at path \"/\" trusting \"ec2.amazonaws.com\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ec2_role",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "eq",
      "value": "/"
     }
    },
    {
     "kind": "attr",
     "select": "ec2_role",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "an omitted Path is the default path /"
  },
  {
   "id": "profile",
   "kind": "exists",
   "tier": "core",
   "select": "prof",
   "quote": "an IAM instance profile"
  },
  {
   "id": "profile_path",
   "tier": "detail",
   "quote": "an IAM instance profile at path \"/\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "prof",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "eq",
      "value": "/"
     }
    },
    {
     "kind": "attr",
     "select": "prof",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "an omitted Path is the default path /"
  },
  {
   "id": "profile_role",
   "kind": "ref",
   "tier": "core",
   "from": "prof",
   "to": "ec2_role",
   "quote": "associated with this role"
  },
  {
   "id": "policy_name",
   "tier": "core",
   "quote": "an IAM policy named \"S3Download\" attached to the role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "named_pol"
    },
    {
     "kind": "exists",
     "select": "named_inline"
    }
   ]
  },
  {
   "id": "policy_attached",
   "tier": "core",
   "quote": "attached to the role",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "named_pol",
     "to": "ec2_role"
    },
    {
     "kind": "attr",
     "select": "ec2_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyName"
      ],
      "op": "eq",
      "value": "S3Download"
     }
    }
   ]
  },
  {
   "id": "act_listbucket",
   "tier": "core",
   "quote": "grants permissions to list, get bucket location, and get objects for the S3 bucket",
   "justify": "list/get bucket location/get objects map to ListBucket/GetBucketLocation/GetObject",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "named_inline",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "named_pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "act_getbucketlocation",
   "tier": "core",
   "quote": "grants permissions to list, get bucket location, and get objects for the S3 bucket",
   "justify": "list/get bucket location/get objects map to ListBucket/GetBucketLocation/GetObject",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "named_inline",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetBucketLocation"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "named_pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetBucketLocation"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "act_getobject",
   "tier": "core",
   "quote": "grants permissions to list, get bucket location, and get objects for the S3 bucket",
   "justify": "list/get bucket location/get objects map to ListBucket/GetBucketLocation/GetObject",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "named_inline",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "named_pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "res_bucket",
   "tier": "core",
   "quote": "for the S3 bucket \"cfnstore\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "named_inline",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":::cfnstore$"
     }
    },
    {
     "kind": "attr",
     "select": "named_pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":::cfnstore$"
     }
    }
   ]
  },
  {
   "id": "res_path",
   "tier": "core",
   "quote": "path \"cfnstore/{CfnBucketName}/*\"",
   "justify": "the parameter default agilefant fills CfnBucketName",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "named_inline",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":::cfnstore/agilefant/\\*$"
     }
    },
    {
     "kind": "attr",
     "select": "named_pol",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":::cfnstore/agilefant/\\*$"
     }
    }
   ]
  },
  {
   "id": "out_profile",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "prof",
   "quote": "exporting the instance profile and instance role in the stack outputs"
  },
  {
   "id": "out_role",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "ec2_role",
   "quote": "exporting the instance profile and instance role in the stack outputs"
  },
  {
   "id": "x_assume",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "ec2_role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "sts:AssumeRole"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
