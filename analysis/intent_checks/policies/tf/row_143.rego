package intent.tf.row_143

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vault": {
   "types": [
    "aws_backup_vault"
   ],
   "where": []
  },
  "decl_vault": {
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
  "plan": {
   "types": [
    "aws_backup_plan"
   ],
   "where": []
  },
  "backup_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [],
     "op": "regex",
     "value": "aws-backup-"
    }
   ]
  },
  "decl_lock": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_backup_vault_lock_configuration"
    }
   ]
  },
  "decl_notif": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_backup_vault_notifications"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vault_exists",
   "kind": "exists",
   "tier": "core",
   "select": "vault",
   "quote": "creates an AWS Backup vault infrastructure"
  },
  {
   "id": "vault_optional_kms",
   "kind": "attr",
   "tier": "detail",
   "select": "decl_vault",
   "cond": {
    "path": [
     "properties",
     "kms_key_arn"
    ],
    "op": "present"
   },
   "quote": "an optional KMS key ARN for vault encryption"
  },
  {
   "id": "vault_optional_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an optional vault policy string",
   "checks": [
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
        "value": "aws_backup_vault_policy"
       }
      ]
     },
     "to": "decl_vault"
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
        "value": "aws_backup_vault_policy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "vault_lock_min_retention",
   "kind": "attr",
   "tier": "core",
   "select": "decl_lock",
   "cond": {
    "path": [
     "properties",
     "min_retention_days"
    ],
    "op": "present"
   },
   "quote": "When a min_retention_days parameter is provided, the template must configure a vault lock"
  },
  {
   "id": "vault_lock_optional_bounds",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with optional max_retention_days and changeable_for_days",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_lock",
     "cond": {
      "path": [
       "properties",
       "max_retention_days"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "decl_lock",
     "cond": {
      "path": [
       "properties",
       "changeable_for_days"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "vault_notifications",
   "kind": "exists",
   "tier": "core",
   "select": "decl_notif",
   "quote": "Optional vault notifications"
  },
  {
   "id": "notification_flag_default_false",
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
      "value": "enable_aws_backup_vault_notifications"
     },
     {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    ]
   },
   "quote": "controlled by a boolean flag enable_aws_backup_vault_notifications (defaulting to false)"
  },
  {
   "id": "notification_failure_events",
   "kind": "any_of",
   "tier": "detail",
   "quote": "route failure events (defaulting to \"BACKUP_JOB_FAILED\" and \"COPY_JOB_FAILED\")",
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
        "op": "eq",
        "value": "aws_backup_vault_notifications"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "BACKUP_JOB_FAILED"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "COPY_JOB_FAILED"
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
         "default"
        ],
        "op": "regex",
        "value": "BACKUP_JOB_FAILED"
       },
       {
        "path": [
         "default"
        ],
        "op": "regex",
        "value": "COPY_JOB_FAILED"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "account_type_default",
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
      "value": "account_type"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "workload"
     }
    ]
   },
   "quote": "an account_type variable defaulting to \"workload\""
  },
  {
   "id": "backup_role_prefixed",
   "kind": "exists",
   "tier": "core",
   "select": "backup_role",
   "quote": "provision an IAM role prefixed with \"aws-backup-\""
  },
  {
   "id": "backup_role_managed_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "with the AWSBackupServiceRolePolicyForBackup managed policy attached",
   "checks": [
    {
     "kind": "ref",
     "to": "backup_role",
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
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForBackup"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "backup_role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWSBackupServiceRolePolicyForBackup"
     }
    }
   ]
  },
  {
   "id": "plan_name",
   "kind": "attr",
   "tier": "core",
   "select": "plan",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "^plan-.*-backup$"
   },
   "quote": "a backup plan named by combining \"plan-\" with the backup name value and the suffix \"-backup\""
  },
  {
   "id": "plan_targets_vault",
   "kind": "ref",
   "tier": "detail",
   "from": "plan",
   "to": "vault",
   "quote": "workload-specific backup plans"
  },
  {
   "id": "rule_windows",
   "kind": "attr",
   "tier": "core",
   "select": "plan",
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "start_window"
      ],
      "op": "eq",
      "value": 60
     },
     {
      "path": [
       "completion_window"
      ],
      "op": "eq",
      "value": 120
     }
    ]
   },
   "quote": "60-minute start window, 120-minute completion window"
  },
  {
   "id": "rule_lifecycle",
   "kind": "attr",
   "tier": "core",
   "select": "plan",
   "cond": {
    "path": [
     "rule",
     "*",
     "lifecycle",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "cold_storage_after"
      ],
      "op": "eq",
      "value": 30
     },
     {
      "path": [
       "delete_after"
      ],
      "op": "eq",
      "value": 120
     }
    ]
   },
   "quote": "cold storage transition after 30 days, deletion after 120 days"
  },
  {
   "id": "rule_recovery_point_tags",
   "kind": "attr",
   "tier": "detail",
   "select": "plan",
   "cond": {
    "path": [
     "rule",
     "*",
     "recovery_point_tags"
    ],
    "op": "present"
   },
   "quote": "recovery point tagging"
  },
  {
   "id": "rule_copy_actions",
   "kind": "attr",
   "tier": "detail",
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
    "value": "(?i)copy_action"
   },
   "quote": "dynamic cross-region or cross-account copy actions"
  },
  {
   "id": "tag_selection",
   "kind": "any_of",
   "tier": "core",
   "quote": "a tag-based backup selection matching key \"Backup\" equal to \"true\" using \"STRINGEQUALS\"",
   "checks": [
    {
     "kind": "ref",
     "to": "plan",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "selection_tag",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "type"
          ],
          "op": "eq",
          "value": "STRINGEQUALS"
         },
         {
          "path": [
           "key"
          ],
          "op": "eq",
          "value": "Backup"
         },
         {
          "path": [
           "value"
          ],
          "op": "eq",
          "value": "true"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "plan",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "condition",
         "*",
         "string_equals",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "key"
          ],
          "op": "regex",
          "value": "(?i)^(aws:ResourceTag/)?Backup$"
         },
         {
          "path": [
           "value"
          ],
          "op": "eq",
          "value": "true"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "selection_uses_backup_role",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_backup_selection"
    ],
    "where": []
   },
   "to": "backup_role",
   "quote": "provision an IAM role prefixed with \"aws-backup-\""
  },
  {
   "id": "resource_selection_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an additional resource-based selection if explicit ARNs are supplied in selection_resources",
   "checks": [
    {
     "kind": "exists",
     "min": 2,
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
        "value": "aws_backup_selection"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "selection_resources"
       }
      ]
     }
    }
   ],
   "justify": "'an additional resource-based selection' -> a second backup selection declared alongside the tag-based one"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
