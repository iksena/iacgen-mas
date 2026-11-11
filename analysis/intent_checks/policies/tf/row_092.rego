package intent.tf.row_092

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "kms_rotation",
   "tier": "core",
   "quote": "a KMS key with key rotation enabled",
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
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "vault_name",
   "tier": "core",
   "quote": "an AWS Backup vault whose name defaults to \"my-backup-vault\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_vault"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "my-backup-vault"
   }
  },
  {
   "id": "vault_encrypted_by_key",
   "tier": "core",
   "quote": "a KMS key with key rotation enabled to encrypt an AWS Backup vault",
   "kind": "ref",
   "from": {
    "types": [
     "aws_backup_vault"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   }
  },
  {
   "id": "vault_tags",
   "tier": "detail",
   "quote": "accepting optional resource tags",
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
     "tags"
    ],
    "op": "present"
   }
  },
  {
   "id": "role_backup_principal",
   "tier": "core",
   "quote": "an IAM role assumed by backup.amazonaws.com",
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
      "op": "regex",
      "value": "backup\\.amazonaws\\.com"
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
      "op": "regex",
      "value": "backup\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "backup.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "role_managed_policy",
   "tier": "core",
   "quote": "attached to the managed AWSBackupServiceRolePolicyForBackup policy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "AWSBackupServiceRolePolicyForBackup$"
       }
      ]
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
      "op": "regex",
      "value": "AWSBackupServiceRolePolicyForBackup$"
     }
    }
   ]
  },
  {
   "id": "plans_named",
   "tier": "core",
   "quote": "three distinct backup plans named after the vault with suffixes \"-daily\", \"-weekly\", and \"-monthly\"",
   "kind": "all_of",
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
       "name"
      ],
      "op": "eq",
      "value": "my-backup-vault-daily"
     }
    },
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
       "name"
      ],
      "op": "eq",
      "value": "my-backup-vault-weekly"
     }
    },
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
       "name"
      ],
      "op": "eq",
      "value": "my-backup-vault-monthly"
     }
    }
   ],
   "justify": "vault default name my-backup-vault plus each stated suffix"
  },
  {
   "id": "plans_windows_vss",
   "tier": "detail",
   "quote": "each containing an advanced backup setting enabling WindowsVSS for EC2 resources",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "advanced_backup_setting",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "resource_type"
      ],
      "op": "eq",
      "value": "EC2"
     },
     {
      "path": [
       "backup_options",
       "WindowsVSS"
      ],
      "op": "eq",
      "value": "enabled"
     }
    ]
   },
   "quantifier": "all"
  },
  {
   "id": "selection_names",
   "tier": "core",
   "quote": "corresponding backup selections named \"daily_backup_selection\", \"weekly_backup_selection\", and \"monthly_backup_selection\"",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "daily_backup_selection"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "weekly_backup_selection"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "monthly_backup_selection"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "selections_all_resources",
   "tier": "detail",
   "quote": "targeting all resources (\"*\")",
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
    "op": "eq",
    "value": "*"
   },
   "quantifier": "all"
  },
  {
   "id": "daily_tag",
   "tier": "detail",
   "quote": "string-like tag conditions on a configurable tag key defaulting to \"backup\" for values \"daily\", \"weekly\", and \"monthly\", respectively",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "daily_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "condition",
       "*",
       "string_like",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)daily"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "daily_backup_selection"
       }
      ]
     },
     "cond": {
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
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)daily"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "daily_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "selection_tag",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)daily"
       }
      ]
     }
    }
   ],
   "justify": "tag key default backup, value daily"
  },
  {
   "id": "weekly_tag",
   "tier": "detail",
   "quote": "string-like tag conditions on a configurable tag key defaulting to \"backup\" for values \"daily\", \"weekly\", and \"monthly\", respectively",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "weekly_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "condition",
       "*",
       "string_like",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)weekly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "weekly_backup_selection"
       }
      ]
     },
     "cond": {
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
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)weekly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "weekly_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "selection_tag",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)weekly"
       }
      ]
     }
    }
   ],
   "justify": "tag key default backup, value weekly"
  },
  {
   "id": "monthly_tag",
   "tier": "detail",
   "quote": "string-like tag conditions on a configurable tag key defaulting to \"backup\" for values \"daily\", \"weekly\", and \"monthly\", respectively",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "monthly_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "condition",
       "*",
       "string_like",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)monthly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "monthly_backup_selection"
       }
      ]
     },
     "cond": {
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
        "op": "eq",
        "value": "aws:ResourceTag/backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)monthly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "monthly_backup_selection"
       }
      ]
     },
     "cond": {
      "path": [
       "selection_tag",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)monthly"
       }
      ]
     }
    }
   ],
   "justify": "tag key default backup, value monthly"
  },
  {
   "id": "tag_conditions_string_like",
   "tier": "detail",
   "quote": "matching string-like tag conditions on a configurable tag key defaulting to \"backup\"",
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
       "condition",
       "*",
       "string_like"
      ],
      "op": "present"
     },
     "quantifier": "all"
    },
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
       "selection_tag",
       "*",
       "type"
      ],
      "op": "regex",
      "value": "(?i)STRINGLIKE"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "daily_rule",
   "tier": "core",
   "quote": "The daily backup plan rule (\"daily_backup_rule\") must use a default schedule of \"cron(0 12 ? * * *)\", a lifecycle deletion threshold of 7 days",
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
       "rule_name"
      ],
      "op": "eq",
      "value": "daily_backup_rule"
     },
     {
      "path": [
       "schedule"
      ],
      "op": "eq",
      "value": "cron(0 12 ? * * *)"
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
   }
  },
  {
   "id": "weekly_rule",
   "tier": "core",
   "quote": "the weekly backup plan rule (\"weekly_backup_rule\") must use a default schedule of \"cron(0 12 ? * 1 *)\" and a lifecycle deletion threshold of 31 days",
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
       "rule_name"
      ],
      "op": "eq",
      "value": "weekly_backup_rule"
     },
     {
      "path": [
       "schedule"
      ],
      "op": "eq",
      "value": "cron(0 12 ? * 1 *)"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 31
     }
    ]
   }
  },
  {
   "id": "monthly_rule",
   "tier": "core",
   "quote": "the monthly backup plan rule (\"monthly_backup_rule\") must use a default schedule of \"cron(0 12 1 * ? *)\" and a lifecycle deletion threshold of 366 days",
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
       "rule_name"
      ],
      "op": "eq",
      "value": "monthly_backup_rule"
     },
     {
      "path": [
       "schedule"
      ],
      "op": "eq",
      "value": "cron(0 12 1 * ? *)"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 366
     }
    ]
   }
  },
  {
   "id": "continuous_backup_false",
   "tier": "detail",
   "quote": "an optional continuous backup flag defaulting to false",
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
        "value": "aws_backup_plan"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "rule",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "rule_name"
        ],
        "op": "eq",
        "value": "daily_backup_rule"
       },
       {
        "path": [
         "enable_continuous_backup"
        ],
        "op": "eq",
        "value": false
       }
      ]
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
       "properties",
       "rule",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "rule_name"
        ],
        "op": "eq",
        "value": "daily_backup_rule"
       },
       {
        "path": [
         "enable_continuous_backup"
        ],
        "op": "regex",
        "value": "var\\."
       }
      ]
     }
    }
   ],
   "justify": "'optional flag defaulting to false' is a variable reference or a literal false"
  },
  {
   "id": "notifications_conditional",
   "tier": "core",
   "quote": "conditionally provision backup vault notifications controlled by a boolean flag defaulting to false",
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
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "notifications_topic",
   "tier": "detail",
   "quote": "sending alerts to a specified SNS topic ARN",
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
        "value": "aws_backup_vault_notifications"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "sns_topic_arn"
      ],
      "op": "regex",
      "value": "var\\."
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
        "op": "regex",
        "value": "(?i)(sns|topic)"
       }
      ]
     }
    }
   ],
   "justify": "'a specified SNS topic ARN' is an input variable"
  },
  {
   "id": "notifications_events",
   "tier": "detail",
   "quote": "a configurable event list defaulting to BACKUP_JOB_FAILED, RESTORE_JOB_FAILED, COPY_JOB_FAILED, S3_BACKUP_OBJECT_FAILED, and S3_RESTORE_OBJECT_FAILED",
   "kind": "any_of",
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
         "properties",
         "backup_vault_events",
         "*"
        ],
        "op": "eq",
        "value": "BACKUP_JOB_FAILED"
       },
       {
        "path": [
         "properties",
         "backup_vault_events",
         "*"
        ],
        "op": "eq",
        "value": "RESTORE_JOB_FAILED"
       },
       {
        "path": [
         "properties",
         "backup_vault_events",
         "*"
        ],
        "op": "eq",
        "value": "COPY_JOB_FAILED"
       },
       {
        "path": [
         "properties",
         "backup_vault_events",
         "*"
        ],
        "op": "eq",
        "value": "S3_BACKUP_OBJECT_FAILED"
       },
       {
        "path": [
         "properties",
         "backup_vault_events",
         "*"
        ],
        "op": "eq",
        "value": "S3_RESTORE_OBJECT_FAILED"
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
         "default",
         "*"
        ],
        "op": "eq",
        "value": "BACKUP_JOB_FAILED"
       },
       {
        "path": [
         "default",
         "*"
        ],
        "op": "eq",
        "value": "RESTORE_JOB_FAILED"
       },
       {
        "path": [
         "default",
         "*"
        ],
        "op": "eq",
        "value": "COPY_JOB_FAILED"
       },
       {
        "path": [
         "default",
         "*"
        ],
        "op": "eq",
        "value": "S3_BACKUP_OBJECT_FAILED"
       },
       {
        "path": [
         "default",
         "*"
        ],
        "op": "eq",
        "value": "S3_RESTORE_OBJECT_FAILED"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "plan_uses_vault",
   "tier": "extra",
   "kind": "ref",
   "from": {
    "types": [
     "aws_backup_plan"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_backup_vault"
    ],
    "where": []
   }
  },
  {
   "id": "selection_uses_plan",
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
   "quote": "along with corresponding backup selections"
  },
  {
   "id": "selection_uses_role",
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
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "an IAM role assumed by backup.amazonaws.com attached to the managed AWSBackupServiceRolePolicyForBackup policy to execute backup operations"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
