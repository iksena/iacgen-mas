package intent.cfn.row_111

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "users": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": []
  },
  "named_users": {
   "types": [
    "AWS::IAM::User"
   ],
   "where": [
    {
     "path": [
      "UserName"
     ],
     "op": "regex",
     "value": "^OHcnappUser0(0[1-9]|1[0-9]|20)$"
    }
   ]
  },
  "policies": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "twenty_users",
   "kind": "exists",
   "select": "users",
   "min": 20,
   "tier": "core",
   "quote": "creates 20 IAM users",
   "max": 20
  },
  {
   "id": "user_names",
   "kind": "exists",
   "select": "named_users",
   "min": 20,
   "tier": "core",
   "quote": "named OHcnappUser001 through OHcnappUser020",
   "justify": "OHcnappUser001 through OHcnappUser020 is 20 names",
   "distinct_path": [
    "UserName"
   ]
  },
  {
   "id": "single_policy",
   "kind": "exists",
   "select": "policies",
   "max": 1,
   "tier": "detail",
   "quote": "a single read-only IAM policy",
   "justify": "single policy"
  },
  {
   "id": "policy_assume_role_any",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::ManagedPolicy",
     "AWS::IAM::Policy"
    ],
    "where": [
     {
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
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:aws:iam::\\*:role/\\*)$"
       }
      ]
     }
    ]
   },
   "tier": "core",
   "quote": "grants these users permission to assume any role",
   "justify": "any role means Resource * or every role ARN"
  },
  {
   "id": "policy_s3_get",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::ManagedPolicy",
     "AWS::IAM::Policy"
    ],
    "where": [
     {
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
    ]
   },
   "tier": "core",
   "quote": "to perform S3 Get operations"
  },
  {
   "id": "policy_read_only",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IAM::ManagedPolicy",
     "AWS::IAM::Policy"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "regex",
    "value": "(?i)^(sts:assumerole|[a-z0-9-]+:(get|list|describe|head)[a-z0-9*]*)$",
    "every": true
   },
   "quantifier": "all",
   "tier": "core",
   "quote": "a single read-only IAM policy",
   "justify": "read-only means the AssumeRole grant plus read-style actions, so no write or wildcard action"
  },
  {
   "id": "policy_attached_to_all_users",
   "kind": "any_of",
   "tier": "core",
   "quote": "the policy should be attached to all 20 users",
   "justify": "all 20 users",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "Users"
        ],
        "op": "len_gte",
        "value": 20
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::User"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     },
     "min": 20
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::User"
      ],
      "where": [
       {
        "path": [
         "Groups",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "min": 20
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::UserToGroupAddition"
      ],
      "where": [
       {
        "path": [
         "Users"
        ],
        "op": "len_gte",
        "value": 20
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_reaches_the_users",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "Users",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "Groups",
         "*"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::User"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Group"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*",
         "ref"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "the policy should be attached to all 20 users"
  },
  {
   "id": "project_default",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "ambassador"
     }
    ]
   },
   "tier": "detail",
   "quote": "project name (default ambassador)"
  },
  {
   "id": "environment_default",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "lab"
     }
    ]
   },
   "tier": "detail",
   "quote": "environment (default lab)"
  },
  {
   "id": "author_default",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "rdevera@tenable.com"
     }
    ]
   },
   "tier": "detail",
   "quote": "author (default rdevera@tenable.com)"
  },
  {
   "id": "version_default",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "v1"
     }
    ]
   },
   "tier": "detail",
   "quote": "version (default v1)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
