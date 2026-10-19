package intent.tf.row_169

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pwp": {
   "types": [
    "aws_iam_account_password_policy"
   ],
   "where": []
  },
  "pab": {
   "types": [
    "aws_s3_account_public_access_block"
   ],
   "where": []
  },
  "dev_group": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "app_developer"
    }
   ]
  },
  "admin_group": {
   "types": [
    "aws_iam_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "app_admin"
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
      "name"
     ],
     "op": "eq",
     "value": "admin"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "password_min_length_12",
   "kind": "attr",
   "select": "pwp",
   "tier": "core",
   "cond": {
    "path": [
     "minimum_password_length"
    ],
    "op": "eq",
    "value": 12
   },
   "quote": "enforce an account-wide IAM password policy with a minimum length of 12"
  },
  {
   "id": "password_complexity",
   "kind": "all_of",
   "tier": "core",
   "quote": "requiring uppercase, lowercase, numbers, symbols",
   "checks": [
    {
     "kind": "attr",
     "select": "pwp",
     "cond": {
      "path": [
       "require_uppercase_characters"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pwp",
     "cond": {
      "path": [
       "require_lowercase_characters"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pwp",
     "cond": {
      "path": [
       "require_numbers"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pwp",
     "cond": {
      "path": [
       "require_symbols"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "password_allow_change",
   "kind": "attr",
   "select": "pwp",
   "tier": "detail",
   "cond": {
    "path": [
     "allow_users_to_change_password"
    ],
    "op": "truthy"
   },
   "quote": "allowing password changes"
  },
  {
   "id": "s3_account_public_access_block",
   "kind": "all_of",
   "tier": "core",
   "quote": "enabling account-level S3 public access block settings (blocking public ACLs, public policies, ignoring public ACLs, and restricting public buckets)",
   "checks": [
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_policy"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "ignore_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "developer_group",
   "kind": "exists",
   "select": "dev_group",
   "tier": "core",
   "quote": "appended with \"_developer\""
  },
  {
   "id": "admin_group",
   "kind": "exists",
   "select": "admin_group",
   "tier": "core",
   "quote": "\"_admin\""
  },
  {
   "id": "group_name_prefix_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "group_name_prefix"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "app"
     }
    ]
   },
   "quote": "a configurable group_name_prefix variable (defaulting to \"app\")"
  },
  {
   "id": "dev_iam_read_only",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attach AWS-managed policies for IAMReadOnlyAccess, IAMUserChangePassword, and IAMUserSSHKeys",
   "checks": [
    {
     "kind": "ref",
     "to": "dev_group",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMReadOnlyAccess"
       }
      ]
     }
    },
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
        "op": "contains",
        "value": "IAMReadOnlyAccess"
       },
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMReadOnlyAccess"
       },
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    }
   ],
   "justify": "AWS-managed policy named in the prompt"
  },
  {
   "id": "dev_change_password",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attach AWS-managed policies for IAMReadOnlyAccess, IAMUserChangePassword, and IAMUserSSHKeys",
   "checks": [
    {
     "kind": "ref",
     "to": "dev_group",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMUserChangePassword"
       }
      ]
     }
    },
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
        "op": "contains",
        "value": "IAMUserChangePassword"
       },
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMUserChangePassword"
       },
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    }
   ],
   "justify": "AWS-managed policy named in the prompt"
  },
  {
   "id": "dev_ssh_keys",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attach AWS-managed policies for IAMReadOnlyAccess, IAMUserChangePassword, and IAMUserSSHKeys",
   "checks": [
    {
     "kind": "ref",
     "to": "dev_group",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMUserSSHKeys"
       }
      ]
     }
    },
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
        "op": "contains",
        "value": "IAMUserSSHKeys"
       },
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "IAMUserSSHKeys"
       },
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    }
   ],
   "justify": "AWS-managed policy named in the prompt"
  },
  {
   "id": "dev_personal_access_keys",
   "kind": "any_of",
   "tier": "detail",
   "quote": "custom policies for managing personal access keys",
   "checks": [
    {
     "kind": "ref",
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
        "value": "iam:CreateAccessKey"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "iam:CreateAccessKey"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:CreateAccessKey"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dev_virtual_mfa_deactivate_needs_mfa",
   "kind": "any_of",
   "tier": "detail",
   "quote": "virtual MFA devices (requiring MFA to deactivate)",
   "checks": [
    {
     "kind": "ref",
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
        "value": "(?s)(iam:DeactivateMFADevice.*aws:MultiFactorAuthPresent|aws:MultiFactorAuthPresent.*iam:DeactivateMFADevice)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "(?s)(iam:DeactivateMFADevice.*aws:MultiFactorAuthPresent|aws:MultiFactorAuthPresent.*iam:DeactivateMFADevice)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?s)(iam:DeactivateMFADevice.*aws:MultiFactorAuthPresent|aws:MultiFactorAuthPresent.*iam:DeactivateMFADevice)"
       }
      ]
     }
    }
   ],
   "justify": "'requiring MFA to deactivate' -> iam:DeactivateMFADevice with aws:MultiFactorAuth* condition"
  },
  {
   "id": "dev_s3_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-gated S3 access",
   "checks": [
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
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
         "aws_iam_role_policy",
         "aws_iam_group_policy",
         "aws_iam_user_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)MultiFactorAuth"
       }
      ]
     }
    }
   ],
   "justify": "'MFA-gated' -> aws:MultiFactorAuth* condition key"
  },
  {
   "id": "dev_s3_createbucket_region_deny",
   "kind": "any_of",
   "tier": "detail",
   "quote": "denying s3:CreateBucket outside a single designated AWS region",
   "checks": [
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?s)(s3:CreateBucket.*aws:RequestedRegion|aws:RequestedRegion.*s3:CreateBucket)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?s)(s3:CreateBucket.*aws:RequestedRegion|aws:RequestedRegion.*s3:CreateBucket)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?s)(s3:CreateBucket.*aws:RequestedRegion|aws:RequestedRegion.*s3:CreateBucket)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
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
         "aws_iam_role_policy",
         "aws_iam_group_policy",
         "aws_iam_user_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:CreateBucket"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)RequestedRegion"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)deny"
       }
      ]
     }
    }
   ],
   "justify": "s3:CreateBucket and 'region' stated (aws:RequestedRegion condition)"
  },
  {
   "id": "dev_s3_state_bucket_deny",
   "kind": "any_of",
   "tier": "detail",
   "quote": "denying all s3:* access to a specific remote-state S3 bucket and its contents",
   "checks": [
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "arn:aws:s3:::[^\"*]+/\\*"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "arn:aws:s3:::[^\"*]+/\\*"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "Deny"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "arn:aws:s3:::[^\"*]+/\\*"
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
         "aws_iam_role_policy",
         "aws_iam_group_policy",
         "aws_iam_user_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)deny"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:\\*"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "/\\*"
       }
      ]
     }
    }
   ],
   "justify": "Deny s3:* on a bucket and its contents (bucket/*) stated"
  },
  {
   "id": "dev_ec2_elb_cw_asg_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "MFA-gated access for EC2, ELB, CloudWatch, AutoScaling",
   "checks": [
    {
     "kind": "ref",
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
        "value": "ec2:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "elasticloadbalancing:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudwatch:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "ec2:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "elasticloadbalancing:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudwatch:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "ec2:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "elasticloadbalancing:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudwatch:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "autoscaling:"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     }
    }
   ],
   "justify": "'ELB' -> elasticloadbalancing: prefix; 'MFA-gated' -> aws:MultiFactorAuth* key"
  },
  {
   "id": "dev_service_linked_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "specific EC2/AutoScaling service-linked roles",
   "checks": [
    {
     "kind": "ref",
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
        "value": "iam:(CreateServiceLinkedRole|PassRole|\\*)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(autoscaling|ec2)[a-z]*\\.amazonaws\\.com|AWSServiceRoleFor(AutoScaling|EC2)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_developer"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "iam:(CreateServiceLinkedRole|PassRole|\\*)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(autoscaling|ec2)[a-z]*\\.amazonaws\\.com|AWSServiceRoleFor(AutoScaling|EC2)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_developer"
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
        "op": "eq",
        "value": "app_developer"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "iam:(CreateServiceLinkedRole|PassRole|\\*)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)(autoscaling|ec2)[a-z]*\\.amazonaws\\.com|AWSServiceRoleFor(AutoScaling|EC2)"
       }
      ]
     }
    }
   ],
   "justify": "access to EC2/AutoScaling service-linked roles: create or pass them, identified by service principal or SLR name"
  },
  {
   "id": "admin_role_named",
   "kind": "exists",
   "select": "admin_role",
   "tier": "core",
   "quote": "create an IAM role named \"admin\""
  },
  {
   "id": "admin_role_trusts_root",
   "kind": "attr",
   "select": "admin_role",
   "tier": "core",
   "cond": {
    "path": [
     "assume_role_policy"
    ],
    "op": "regex",
    "value": "arn:aws:iam::[^\"]*:root"
   },
   "quote": "can be assumed by the account root principal"
  },
  {
   "id": "admin_role_full_access_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to a policy granting full administrative access conditioned on active MFA",
   "checks": [
    {
     "kind": "ref",
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
        "value": "\"Action\"\\s*:\\s*(\\[\\s*)?\"\\*\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "admin"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "\"Action\"\\s*:\\s*(\\[\\s*)?\"\\*\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "admin"
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
         "role"
        ],
        "op": "eq",
        "value": "admin"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "\"Action\"\\s*:\\s*(\\[\\s*)?\"\\*\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "admin_role",
     "cond": {
      "path": [
       "inline_policy",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "\"Action\"\\s*:\\s*(\\[\\s*)?\"\\*\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     }
    }
   ],
   "justify": "'full administrative access' -> Action \"*\"; 'active MFA' -> aws:MultiFactorAuth* key"
  },
  {
   "id": "admin_group_assume_admin_mfa",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach a policy to the admin group allowing members to assume this admin role when MFA is present",
   "checks": [
    {
     "kind": "ref",
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
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "role/admin"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "group"
        ],
        "op": "eq",
        "value": "app_admin"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "role/admin"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     },
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "groups",
         "*"
        ],
        "op": "eq",
        "value": "app_admin"
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
        "op": "eq",
        "value": "app_admin"
       },
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
        "value": "role/admin"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
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
         "aws_iam_group_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "sts:AssumeRole"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "role/admin|aws_iam_role\\.[A-Za-z0-9_-]+"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws:MultiFactorAuth(Present|Age)"
       }
      ]
     }
    }
   ],
   "justify": "'assume this admin role when MFA is present' -> sts:AssumeRole + aws:MultiFactorAuth*; planned policy may be unknown, declared document accepted"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
