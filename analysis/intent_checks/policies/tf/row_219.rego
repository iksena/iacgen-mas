package intent.tf.row_219

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
  "policy": {
   "types": [
    "aws_iam_policy",
    "aws_iam_group_policy"
   ],
   "where": []
  },
  "group": {
   "types": [
    "aws_iam_group"
   ],
   "where": []
  },
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment"
   ],
   "where": []
  },
  "member": {
   "types": [
    "aws_iam_user_group_membership",
    "aws_iam_group_membership"
   ],
   "where": []
  },
  "named": {
   "types": [
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_group_policy",
    "aws_iam_group",
    "aws_iam_user"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM role with wild-card principal assume-role permissions",
   "select": "role"
  },
  {
   "id": "role_wildcard_principal",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM role with wild-card principal assume-role permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(AWS|Principal|identifiers)\\W{1,6}\\*"
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
        "op": "regex",
        "value": "(AWS|Principal|identifiers)\\W{1,6}\\*"
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
        "op": "regex",
        "value": "(AWS|Principal|identifiers)\\W{1,6}\\*"
       }
      ]
     }
    }
   ],
   "justify": "wild-card principal means '*'"
  },
  {
   "id": "role_trust_assume",
   "kind": "any_of",
   "tier": "detail",
   "quote": "wild-card principal assume-role permissions",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "sts:AssumeRole([^A-Za-z]|$)"
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
        "op": "regex",
        "value": "sts:AssumeRole([^A-Za-z]|$)"
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
        "op": "regex",
        "value": "sts:AssumeRole([^A-Za-z]|$)"
       }
      ]
     }
    }
   ],
   "justify": "assume-role action is sts:AssumeRole"
  },
  {
   "id": "policy",
   "kind": "exists",
   "tier": "core",
   "quote": "a policy granting role assumption permissions for that role",
   "select": "policy"
  },
  {
   "id": "policy_grants_assume_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy granting role assumption permissions for that role",
   "checks": [
    {
     "kind": "attr",
     "select": "policy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "sts:AssumeRole([^A-Za-z]|$)"
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
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole([^A-Za-z]|$)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "policy",
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
        "op": "regex",
        "value": "sts:AssumeRole([^A-Za-z]|$)"
       }
      ]
     }
    }
   ],
   "justify": "role assumption is sts:AssumeRole"
  },
  {
   "id": "policy_for_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy granting role assumption permissions for that role",
   "checks": [
    {
     "kind": "ref",
     "from": "policy",
     "to": "role"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "to": "role"
    }
   ]
  },
  {
   "id": "group",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM group with the policy attached",
   "select": "group"
  },
  {
   "id": "attach_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM group with the policy attached",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": "group"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "to": "group"
    }
   ]
  },
  {
   "id": "attach_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM group with the policy attached",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "to": "group"
    }
   ]
  },
  {
   "id": "user",
   "kind": "exists",
   "tier": "core",
   "quote": "an IAM user",
   "select": "user"
  },
  {
   "id": "membership_user",
   "kind": "ref",
   "tier": "core",
   "quote": "a group membership binding the user to the group",
   "from": "member",
   "to": "user"
  },
  {
   "id": "membership_group",
   "kind": "ref",
   "tier": "core",
   "quote": "a group membership binding the user to the group",
   "from": "member",
   "to": "group"
  },
  {
   "id": "names_prefixed",
   "kind": "attr",
   "tier": "core",
   "quote": "all resource names use prefix \"prod-ci-\"",
   "select": "named",
   "quantifier": "all",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "\"name(_prefix)?\": \"prod-ci-"
   }
  },
  {
   "id": "names_append_suffix",
   "kind": "attr",
   "tier": "detail",
   "quote": "append a configurable name_suffix variable",
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
       "aws_iam_policy",
       "aws_iam_group_policy",
       "aws_iam_group",
       "aws_iam_user"
      ]
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "properties",
     "name"
    ],
    "op": "regex",
    "value": "(?i)suffix"
   }
  },
  {
   "id": "name_suffix_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "append a configurable name_suffix variable defaulting to an empty string",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "name_suffix"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
