package intent.tf.row_217

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "self_policy": {
   "types": [
    "aws_iam_policy",
    "aws_iam_group_policy"
   ],
   "where": [
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(ChangePassword|(Create|Update)LoginProfile|\\*\")"
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(CreateAccessKey|UpdateAccessKey|\\*AccessKey\\*?|\\*\")"
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(CreateVirtualMFADevice|EnableMFADevice|\\*MFADevice\\*?|\\*\")"
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(DeactivateMFADevice|\\*MFADevice\\*?|\\*\")"
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(List(VirtualMFADevices|MFADevices|\\*)|\\*\")"
    },
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "iam:(GetAccountPasswordPolicy|Get\\*|\\*\")"
    }
   ]
  },
  "admin_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "sts:AssumeRole"
    },
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "regex",
     "value": ":root\""
    },
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "aws:MultiFactorAuthPresent"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "two_groups",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "min": 2,
   "tier": "core",
   "quote": "across both an admin group and a non-admin group"
  },
  {
   "id": "self_management_policy",
   "kind": "exists",
   "select": "self_policy",
   "tier": "core",
   "quote": "allowing members to manage their own passwords, access keys, virtual MFA devices, and list account MFA devices and password policies"
  },
  {
   "id": "self_policy_attached_to_groups",
   "kind": "any_of",
   "tier": "core",
   "quote": "A self-management policy must be attached to both groups",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(ChangePassword|(Create|Update)LoginProfile|\\*\")"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(DeactivateMFADevice|\\*MFADevice\\*?|\\*\")"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(ChangePassword|(Create|Update)LoginProfile|\\*\")"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(DeactivateMFADevice|\\*MFADevice\\*?|\\*\")"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(ChangePassword|(Create|Update)LoginProfile|\\*\")"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(DeactivateMFADevice|\\*MFADevice\\*?|\\*\")"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "self_policy_both_groups",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attached to both groups",
   "checks": [
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "aws_iam_group_policy_attachment",
       "aws_iam_group_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "groups"
      ],
      "op": "len_gte",
      "value": 2
     }
    }
   ],
   "justify": "\"attached to both groups\" = the two groups the prompt names"
  },
  {
   "id": "deactivate_mfa_requires_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "requiring active MFA specifically to deactivate their virtual MFA devices",
   "checks": [
    {
     "kind": "attr",
     "select": "self_policy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "MultiFactorAuthPresent\"\\s*:\\s*(\\[\\s*)?\"?true"
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
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "eq",
        "value": "iam:DeactivateMFADevice"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
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
         "aws_iam_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "DeactivateMFADevice"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "admin_role_trust_root_mfa",
   "kind": "exists",
   "select": "admin_role",
   "tier": "core",
   "quote": "requiring MFA present for both role assumption and the role's trust policy targeting the account root principal"
  },
  {
   "id": "admin_role_administrator_access",
   "kind": "any_of",
   "tier": "core",
   "quote": "The admin role must be attached to the AWS-managed AdministratorAccess policy",
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
         "policy_arn"
        ],
        "op": "eq",
        "value": "arn:aws:iam::aws:policy/AdministratorAccess"
       }
      ]
     },
     "to": "admin_role"
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
         "policy_arn"
        ],
        "op": "eq",
        "value": "arn:aws:iam::aws:policy/AdministratorAccess"
       }
      ]
     },
     "to": "admin_role"
    },
    {
     "kind": "attr",
     "select": "admin_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "eq",
      "value": "arn:aws:iam::aws:policy/AdministratorAccess"
     }
    }
   ],
   "justify": "prompt names the AWS-managed AdministratorAccess policy; its ARN is fixed"
  },
  {
   "id": "assume_admin_role_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy granting permission to assume a dedicated admin role",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "eq",
        "value": "sts:AssumeRole"
       }
      ]
     },
     "to": "admin_role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "to": "admin_role"
    }
   ]
  },
  {
   "id": "assume_admin_role_requires_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "strictly requiring MFA present for both role assumption",
   "checks": [
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
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "eq",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "principals"
        ],
        "op": "len_eq",
        "value": 0
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "aws:MultiFactorAuthPresent"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "aws:MultiFactorAuthPresent"
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
         "aws_iam_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "assume_policy_attached_to_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The admin group must additionally receive a policy",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sts:AssumeRole"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "sts:AssumeRole"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_group"
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
     "to": "admin_role"
    },
    {
     "kind": "exists",
     "min": 3,
     "select": {
      "types": [
       "aws_iam_group_policy_attachment",
       "aws_iam_group_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": []
     }
    }
   ],
   "justify": "fallback counts: self-policy on two groups + one assume-role policy on the admin group (3 group attachments, or 2 multi-group attachments)"
  },
  {
   "id": "conditional_memberships",
   "kind": "exists",
   "min": 1,
   "tier": "detail",
   "quote": "both groups must conditionally manage user memberships based on provided lists of admin and non-admin user names",
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
       "aws_iam_group_membership",
       "aws_iam_user_group_membership"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "label_variables",
   "kind": "all_of",
   "tier": "detail",
   "quote": "using namespace, environment, name, tags, and attributes variables",
   "checks": [
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
        "op": "eq",
        "value": "namespace"
       }
      ]
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
        "op": "eq",
        "value": "environment"
       }
      ]
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
        "op": "eq",
        "value": "tags"
       }
      ]
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
        "op": "eq",
        "value": "attributes"
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
