package intent.tf.row_129

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "selection_rds",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_selection"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "resources",
     "*"
    ],
    "op": "regex",
    "value": "(?i)^arn:aws[\\w-]*:rds:.*\\*"
   },
   "quote": "a comprehensive AWS Backup solution for all RDS databases in the account",
   "justify": "'all RDS databases' means a wildcard RDS ARN rather than named instances"
  },
  {
   "id": "daily_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "schedule"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(0 2 [*?] \\* [*?] \\*\\)$"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 7
     }
    ]
   },
   "quote": "daily (retained 7 days, triggered at 2 AM UTC)",
   "justify": "2 AM UTC daily is cron minute 0, hour 2, any day"
  },
  {
   "id": "weekly_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "schedule"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(0 2 [*?] \\* (7|sat) \\*\\)$"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 30
     }
    ]
   },
   "quote": "weekly (retained 30 days, triggered Saturdays at 2 AM UTC)",
   "justify": "Saturday is day-of-week 7 or SAT in AWS cron"
  },
  {
   "id": "monthly_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "schedule"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(0 3 1 \\* [*?] \\*\\)$"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 365
     }
    ]
   },
   "quote": "monthly (retained 365 days, triggered on the 1st at 3 AM UTC)",
   "justify": "1st of month at 3 AM UTC is cron minute 0, hour 3, day 1"
  },
  {
   "id": "yearly_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "schedule"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(0 4 1 (1|jan) [*?] \\*\\)$"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 2555
     }
    ]
   },
   "quote": "yearly (retained 2555 days, triggered on January 1st at 4 AM UTC)",
   "justify": "January is month 1 or JAN"
  },
  {
   "id": "vault_kms_encrypted",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "aws_backup_vault"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "kms_key_arn"
      ],
      "op": "present"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "kms_key_arn"
      ],
      "op": "present"
     },
     "quantifier": "all"
    }
   ],
   "quote": "each using KMS-encrypted backup vaults"
  },
  {
   "id": "kms_key_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "KMS-encrypted backup vaults"
  },
  {
   "id": "cross_region_vault",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": []
     },
     "distinct_path": [
      "region"
     ],
     "min": 2
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
        "value": "aws_backup_vault"
       },
       {
        "path": [
         "properties",
         "region"
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
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_backup_vault"
       },
       {
        "path": [
         "properties",
         "provider"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "quote": "a copy action to a cross-region vault in a configurable secondary AWS region",
   "justify": "a cross-region vault means vaults in at least two regions"
  },
  {
   "id": "copy_to_cross_region_vault",
   "tier": "core",
   "kind": "any_of",
   "quote": "including a copy action to a cross-region vault",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
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
        "value": "aws_backup_vault"
       },
       {
        "path": [
         "properties",
         "region"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
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
        "value": "aws_backup_vault"
       },
       {
        "path": [
         "properties",
         "provider"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "secondary_region_configurable",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "^[a-z]{2}(-gov)?-[a-z]+-[0-9]$"
   },
   "quote": "a configurable secondary AWS region",
   "justify": "configurable means the secondary region is a variable whose default is a region name"
  },
  {
   "id": "copy_action_each_plan",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "copy_action"
    ],
    "op": "present",
    "every": true
   },
   "quantifier": "all",
   "quote": "each using KMS-encrypted backup vaults and including a copy action"
  },
  {
   "id": "cross_account_copy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rule",
       "*",
       "copy_action",
       "*",
       "destination_vault_arn"
      ],
      "op": "contains",
      "value": "433568766270"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_backup_plan"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "destination_vault_arn\"?: ?\"(arn:[^\"]*:backup:[^\"]*)?\\$\\{(var|local)\\."
     }
    }
   ],
   "quote": "an optional cross-account copy to a specified destination account"
  },
  {
   "id": "cross_account_default_id",
   "tier": "detail",
   "kind": "any_of",
   "quote": "defaulting to account ID 433568766270",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rule",
       "*",
       "copy_action",
       "*",
       "destination_vault_arn"
      ],
      "op": "contains",
      "value": "433568766270"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "433568766270"
     }
    }
   ]
  },
  {
   "id": "cross_account_on_by_default",
   "tier": "detail",
   "kind": "attr",
   "quote": "when enabled via a boolean variable that defaults to true",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "copy_action"
    ],
    "op": "len_gte",
    "value": 2
   },
   "justify": "enabled by default means each planned rule carries the cross-region copy plus the cross-account copy"
  },
  {
   "id": "iam_role_backup",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "backup.amazonaws.com"
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "backup.amazonaws.com"
     }
    }
   ],
   "quote": "create the necessary IAM role"
  },
  {
   "id": "iam_role_service_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "contains",
      "value": "AWSBackupServiceRolePolicyForBackup"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWSBackupServiceRolePolicyForBackup"
     }
    },
    {
     "kind": "attr",
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy_arn"
      ],
      "op": "contains",
      "value": "AWSBackupServiceRolePolicyForBackup"
     }
    }
   ],
   "quote": "IAM role with the AWS Backup service role policy"
  },
  {
   "id": "role_attachment_ref",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
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
   "quote": "IAM role with the AWS Backup service role policy"
  },
  {
   "id": "selection_uses_role",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_selection"
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
        "value": "aws_backup_selection"
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
   "quote": "create the necessary IAM role"
  },
  {
   "id": "exclude_rds_by_arn",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "not_resources"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "not_resources"
     }
    }
   ],
   "quote": "allow excluding specific RDS instances by ARN via a list variable",
   "justify": "excluding resources from an AWS Backup selection is the not_resources argument"
  },
  {
   "id": "daily_plan_toggle",
   "tier": "detail",
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
      "value": "aws_backup_plan"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "cron\\(0 2 [*?] \\* [*?] \\*\\)"
     }
    ]
   },
   "quote": "use a variable to control whether the daily backup plan is created (defaulting to true)",
   "justify": "a variable controlling creation means the plan is count/for_each gated"
  },
  {
   "id": "x_kms_rotation",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "selection_assigned_to_plan",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_backup_selection"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "quote": "a comprehensive AWS Backup solution for all RDS databases in the account"
  },
  {
   "id": "x_copy_lifecycle",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "copy_action",
     "*",
     "lifecycle",
     "*",
     "delete_after"
    ],
    "op": "present"
   }
  },
  {
   "id": "extra_type_aws_kms_key_policy",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_kms_key_policy"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
