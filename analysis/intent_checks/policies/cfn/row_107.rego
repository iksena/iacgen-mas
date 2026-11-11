package intent.cfn.row_107

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "vault": {
   "types": [
    "AWS::Backup::BackupVault"
   ],
   "where": []
  },
  "plan": {
   "types": [
    "AWS::Backup::BackupPlan"
   ],
   "where": []
  },
  "role": {
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
     "value": "backup.amazonaws.com"
    }
   ]
  },
  "sel": {
   "types": [
    "AWS::Backup::BackupSelection"
   ],
   "where": []
  },
  "tagopt": {
   "types": [
    "AWS::ServiceCatalog::TagOption"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "daily_plan",
   "kind": "attr",
   "select": "plan",
   "cond": {
    "path": [
     "BackupPlan",
     "BackupPlanRule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* [*?]( \\S+)?\\)$"
     },
     {
      "path": [
       "Lifecycle",
       "DeleteAfterDays"
      ],
      "op": "eq",
      "value": 14
     }
    ]
   },
   "tier": "core",
   "quote": "daily backups running each day at 5 AM UTC and retaining for 14 days",
   "justify": "each day = every day-of-month and day-of-week; 5 AM = hour field 5"
  },
  {
   "id": "weekly_plan",
   "kind": "attr",
   "select": "plan",
   "cond": {
    "path": [
     "BackupPlan",
     "BackupPlanRule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* (1|SUN)( \\S+)?\\)$"
     },
     {
      "path": [
       "Lifecycle",
       "DeleteAfterDays"
      ],
      "op": "eq",
      "value": 56
     }
    ]
   },
   "tier": "core",
   "quote": "weekly backups each Sunday at 5 AM UTC retaining for 56 days",
   "justify": "Sunday is 1 or SUN in cron; 5 AM = hour field 5"
  },
  {
   "id": "monthly_plan",
   "kind": "attr",
   "select": "plan",
   "cond": {
    "path": [
     "BackupPlan",
     "BackupPlanRule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(\\S+ 0?5 0?1 \\* [*?]( \\S+)?\\)$"
     },
     {
      "path": [
       "Lifecycle",
       "DeleteAfterDays"
      ],
      "op": "eq",
      "value": 365
     }
    ]
   },
   "tier": "core",
   "quote": "monthly backups on the first day of each month at 5 AM UTC retaining for 365 days",
   "justify": "first day of month = day-of-month 1; 5 AM = hour field 5"
  },
  {
   "id": "three_vaults",
   "kind": "exists",
   "select": "vault",
   "min": 3,
   "tier": "core",
   "quote": "separate encrypted backup vaults for each schedule",
   "justify": "daily, weekly and monthly schedules"
  },
  {
   "id": "vaults_encrypted",
   "kind": "attr",
   "select": "vault",
   "cond": {
    "path": [
     "EncryptionKeyArn"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "tier": "core",
   "quote": "separate encrypted backup vaults for each schedule"
  },
  {
   "id": "kms_key_rotation",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "a KMS key with rotation enabled"
  },
  {
   "id": "vault_uses_key",
   "kind": "ref",
   "from": "vault",
   "to": "key",
   "tier": "detail",
   "quote": "encrypted backup vaults"
  },
  {
   "id": "backup_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "an IAM service role for AWS Backup"
  },
  {
   "id": "select_daily",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "ListOfTags",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "daily"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "Conditions",
       "StringEquals",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "regex",
        "value": "(?i)backup$"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "daily"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "tag-based backup selections that use the specified tags"
  },
  {
   "id": "select_weekly",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "ListOfTags",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "weekly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "Conditions",
       "StringEquals",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "regex",
        "value": "(?i)backup$"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "weekly"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "tag-based backup selections that use the specified tags"
  },
  {
   "id": "select_monthly",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "ListOfTags",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "monthly"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "BackupSelection",
       "Conditions",
       "StringEquals",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "ConditionKey"
        ],
        "op": "regex",
        "value": "(?i)backup$"
       },
       {
        "path": [
         "ConditionValue"
        ],
        "op": "eq",
        "value": "monthly"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "tag-based backup selections that use the specified tags"
  },
  {
   "id": "selection_uses_role",
   "kind": "ref",
   "from": "sel",
   "to": "role",
   "tier": "detail",
   "quote": "tag-based backup selections"
  },
  {
   "id": "selection_in_plan",
   "kind": "ref",
   "from": "sel",
   "to": "plan",
   "tier": "detail",
   "quote": "tag-based backup selections"
  },
  {
   "id": "monthly_tag_uses_schedule",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "ListOfTags",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "eq",
          "value": "backup"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "monthly"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 0?1 \\* [*?]( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "Conditions",
         "StringEquals",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "regex",
          "value": "(?i)backup$"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "monthly"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 0?1 \\* [*?]( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    }
   ],
   "quote": "tag-based backup selections that use the specified tags",
   "justify": "the prompt ties each tag value to its schedule; 5 AM is hour field 5"
  },
  {
   "id": "weekly_tag_uses_schedule",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "ListOfTags",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "eq",
          "value": "backup"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "weekly"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* (1|SUN)( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "Conditions",
         "StringEquals",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "regex",
          "value": "(?i)backup$"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "weekly"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* (1|SUN)( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    }
   ],
   "quote": "tag-based backup selections that use the specified tags",
   "justify": "the prompt ties each tag value to its schedule; 5 AM is hour field 5"
  },
  {
   "id": "daily_tag_uses_schedule",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "ListOfTags",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "eq",
          "value": "backup"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "daily"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* [*?]( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Backup::BackupSelection"
      ],
      "where": [
       {
        "path": [
         "BackupSelection",
         "Conditions",
         "StringEquals",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ConditionKey"
          ],
          "op": "regex",
          "value": "(?i)backup$"
         },
         {
          "path": [
           "ConditionValue"
          ],
          "op": "eq",
          "value": "daily"
         }
        ]
       }
      ]
     },
     "to": {
      "types": [
       "AWS::Backup::BackupPlan"
      ],
      "where": [
       {
        "path": [
         "BackupPlan",
         "BackupPlanRule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "ScheduleExpression"
          ],
          "op": "regex",
          "value": "(?i)^cron\\(\\S+ 0?5 [*?] \\* [*?]( \\S+)?\\)$"
         }
        ]
       }
      ]
     }
    }
   ],
   "quote": "tag-based backup selections that use the specified tags",
   "justify": "the prompt ties each tag value to its schedule; 5 AM is hour field 5"
  },
  {
   "id": "plan_targets_vault",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "plan",
     "to": "vault"
    },
    {
     "kind": "join",
     "from": "plan",
     "from_path": [
      "BackupPlan",
      "BackupPlanRule",
      "*",
      "TargetBackupVault"
     ],
     "to": "vault",
     "to_path": [
      "BackupVaultName"
     ]
    }
   ],
   "tier": "detail",
   "quote": "separate encrypted backup vaults for each schedule"
  },
  {
   "id": "separate_vault_per_schedule",
   "kind": "exists",
   "select": "plan",
   "distinct_path": [
    "BackupPlan",
    "BackupPlanRule",
    "*",
    "TargetBackupVault"
   ],
   "min": 3,
   "tier": "core",
   "quote": "separate encrypted backup vaults for each schedule",
   "justify": "daily, weekly and monthly schedules each target their own vault"
  },
  {
   "id": "tag_options",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ServiceCatalog::TagOption"
      ],
      "where": [
       {
        "path": [
         "Key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "Value"
        ],
        "op": "eq",
        "value": "daily"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ServiceCatalog::TagOption"
      ],
      "where": [
       {
        "path": [
         "Key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "Value"
        ],
        "op": "eq",
        "value": "weekly"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ServiceCatalog::TagOption"
      ],
      "where": [
       {
        "path": [
         "Key"
        ],
        "op": "eq",
        "value": "backup"
       },
       {
        "path": [
         "Value"
        ],
        "op": "eq",
        "value": "monthly"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "provision Service Catalog TagOption key-value pairs for the backup tag values"
  },
  {
   "id": "x_role_managed_policy",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "AWSBackupServiceRolePolicyForBackup"
   },
   "tier": "extra"
  },
  {
   "id": "x_tagoption_active",
   "kind": "attr",
   "select": "tagopt",
   "cond": {
    "path": [
     "Active"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
