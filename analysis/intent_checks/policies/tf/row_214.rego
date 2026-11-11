package intent.tf.row_214

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "name_var_default",
   "kind": "exists",
   "tier": "core",
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
      "value": "awscademo-"
     }
    ]
   },
   "quote": "configurable name variable defaulting to \"awscademo-\""
  },
  {
   "id": "groups",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": []
   },
   "quote": "Provision three distinct IAM groups",
   "min": 3
  },
  {
   "id": "groups_prefixed",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^awscademo-"
     }
    ]
   },
   "quote": "named with the prefix",
   "min": 3,
   "distinct_path": [
    "name"
   ],
   "justify": "default prefix awscademo-"
  },
  {
   "id": "group_superadmin",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)super.?admin"
     }
    ]
   },
   "quote": "an MFA superadmin group"
  },
  {
   "id": "demo_group_policy_attached",
   "kind": "any_of",
   "tier": "core",
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
        "value": "iam:ChangePassword"
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
        "op": "eq",
        "value": "aws_iam_group_policy_attachment"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "iam:ChangePassword"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:ChangePassword"
       }
      ]
     }
    }
   ],
   "quote": "a demo users group attached to a custom self-management policy"
  },
  {
   "id": "selfmgmt_password",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(ChangePassword|\\*(?:[\"'\\],\\s]|$))"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(ChangePassword|\\*(?:[\"'\\],\\s]|$))"
       }
      ]
     }
    }
   ],
   "quote": "allowing users to change their own passwords"
  },
  {
   "id": "selfmgmt_access_keys",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateAccessKey|\\*AccessKey\\*|\\*(?:[\"'\\],\\s]|$))"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateAccessKey|\\*AccessKey\\*|\\*(?:[\"'\\],\\s]|$))"
       }
      ]
     }
    }
   ],
   "quote": "manage access keys",
   "justify": "managing access keys implies iam access key actions"
  },
  {
   "id": "selfmgmt_ssh_keys",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(UploadSSHPublicKey|\\*SSHPublicKey\\*|\\*(?:[\"'\\],\\s]|$))"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(UploadSSHPublicKey|\\*SSHPublicKey\\*|\\*(?:[\"'\\],\\s]|$))"
       }
      ]
     }
    }
   ],
   "quote": "upload SSH public keys"
  },
  {
   "id": "selfmgmt_mfa",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateVirtualMFADevice|EnableMFADevice|\\*MFADevice\\*|\\*(?:[\"'\\],\\s]|$))"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateVirtualMFADevice|EnableMFADevice|\\*MFADevice\\*|\\*(?:[\"'\\],\\s]|$))"
       }
      ]
     }
    }
   ],
   "quote": "manage virtual MFA devices"
  },
  {
   "id": "selfmgmt_deactivate_mfa_only_with_mfa",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)(DeactivateMFADevice.{0,900}MultiFactorAuthPresent|MultiFactorAuthPresent.{0,900}DeactivateMFADevice)"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?is)(DeactivateMFADevice.{0,900}MultiFactorAuthPresent|MultiFactorAuthPresent.{0,900}DeactivateMFADevice)"
       }
      ]
     }
    }
   ],
   "quote": "including deactivating their own MFA only when MFA is present",
   "justify": "MFA-present condition is aws:MultiFactorAuthPresent"
  },
  {
   "id": "readonly_group_policy",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/ReadOnlyAccess$"
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
        "op": "eq",
        "value": "aws_iam_group_policy_attachment"
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "regex",
        "value": "ReadOnlyAccess"
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
        "op": "eq",
        "value": "aws_iam_group_policy_attachment"
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
        "value": "data.aws_iam_policy"
       },
       {
        "path": [
         "properties",
         "arn"
        ],
        "op": "regex",
        "value": "ReadOnlyAccess"
       }
      ]
     }
    }
   ],
   "quote": "a read-only users group attached to the AWS managed ReadOnlyAccess policy"
  },
  {
   "id": "admin_role",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "create an administrative IAM role"
  },
  {
   "id": "admin_role_name_prefix",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name_prefix"
        ],
        "op": "regex",
        "value": "^awscademo-"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "^awscademo-"
       }
      ]
     }
    }
   ],
   "quote": "an administrative IAM role named with the prefix and truncated to a 31-character name prefix",
   "justify": "default prefix awscademo-"
  },
  {
   "id": "role_root_assume",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "(?i):root"
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "regex",
        "value": "(?i):root"
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
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i):root"
       }
      ]
     }
    }
   ],
   "quote": "permitting account root assume-role access"
  },
  {
   "id": "role_session",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "max_session_duration"
    ],
    "op": "eq",
    "value": 43200
   },
   "quote": "a maximum session duration of 12 hours (43200 seconds)"
  },
  {
   "id": "admin_policy_full_mfa",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)[\"\\']?Actions?[\"\\']?\\s*:\\s*(\\[\\s*)?[\"\\']\\*[\"\\']"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)[\"\\']?Actions?[\"\\']?\\s*:\\s*(\\[\\s*)?[\"\\']\\*[\"\\']"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    }
   ],
   "quote": "an admin policy that grants full administrator permissions conditioned on MFA presence",
   "justify": "full administrator permissions means Action *"
  },
  {
   "id": "admin_policy_on_role",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
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
        "value": "(?i)[\"']?Actions?[\"']?\\s*:\\s*(\\[\\s*)?[\"']\\*[\"']"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)[\"']?Actions?[\"']?\\s*:\\s*(\\[\\s*)?[\"']\\*[\"']"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)[\"']?Actions?[\"']?\\s*:\\s*(\\[\\s*)?[\"']\\*[\"']"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)[\"']?Actions?[\"']?\\s*:\\s*(\\[\\s*)?[\"']\\*[\"']"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ],
   "quote": "accompanied by an admin policy that grants full administrator permissions",
   "justify": "full administrator permissions means Action *"
  },
  {
   "id": "assume_policy_mfa",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
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
         "aws_iam_user_policy",
         "aws_iam_group_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    }
   ],
   "quote": "allowing group members to assume this admin role when MFA is present"
  },
  {
   "id": "assume_policy_attached_to_superadmins",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "regex",
        "value": "(?i)super.?admin"
       }
      ]
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
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "regex",
        "value": "(?i)super.?admin"
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_group_policy"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "regex",
        "value": "(?i)super.?admin"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
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
        "op": "eq",
        "value": "aws_iam_group_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "MultiFactorAuthPresent"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)super.?admin"
       }
      ]
     }
    }
   ],
   "quote": "attach a group policy to the MFA superadmin group allowing group members to assume this admin role when MFA is present"
  },
  {
   "id": "assume_policy_targets_role",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
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
        "op": "eq",
        "value": "aws_iam_policy"
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
        "value": "aws_iam_role"
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
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    }
   ],
   "quote": "allowing group members to assume this admin role"
  },
  {
   "id": "x_role_attach_policy",
   "kind": "ref",
   "tier": "extra",
   "from": {
    "types": [
     "aws_iam_role_policy_attachment"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_policy"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
