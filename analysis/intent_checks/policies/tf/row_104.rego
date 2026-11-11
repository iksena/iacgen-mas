package intent.tf.row_104

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "kms_key",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "provision a shared KMS key"
  },
  {
   "id": "kms_deletion",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 10
   },
   "quote": "a 10-day deletion window"
  },
  {
   "id": "kms_rotation",
   "tier": "core",
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
   },
   "quote": "key rotation enabled"
  },
  {
   "id": "role_name",
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
       "name"
      ],
      "op": "eq",
      "value": "Bronze_Backup_Role"
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
       "name"
      ],
      "op": "eq",
      "value": "Bronze_Backup_Role"
     }
    }
   ],
   "quote": "an IAM role named \"Bronze_Backup_Role\""
  },
  {
   "id": "role_principal",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
       }
      ]
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
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
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
   "quote": "assumed by backup.amazonaws.com"
  },
  {
   "id": "attach_backup",
   "tier": "core",
   "kind": "any_of",
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
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForBackup"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
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
        "value": "aws_iam_role_policy_attachment"
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForBackup"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
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
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
       }
      ]
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
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForBackup"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
       }
      ]
     }
    }
   ],
   "quote": "IAM role named \"Bronze_Backup_Role\" assumed by backup.amazonaws.com attached to the AWSBackupServiceRolePolicyForBackup and AWSBackupServiceRolePolicyForRestores managed policies"
  },
  {
   "id": "attach_restores",
   "tier": "core",
   "kind": "any_of",
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
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForRestores"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
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
        "value": "aws_iam_role_policy_attachment"
       },
       {
        "path": [
         "properties",
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForRestores"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
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
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AWSBackupServiceRolePolicyForRestores"
     }
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
        "op": "contains",
        "value": "AWSBackupServiceRolePolicyForRestores"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Role"
       }
      ]
     }
    }
   ],
   "quote": "IAM role named \"Bronze_Backup_Role\" assumed by backup.amazonaws.com attached to the AWSBackupServiceRolePolicyForBackup and AWSBackupServiceRolePolicyForRestores managed policies"
  },
  {
   "id": "vaults",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     }
    }
   ],
   "quote": "a dedicated backup vault encrypted with the shared KMS key"
  },
  {
   "id": "vaults_kms",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Vault"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Vault"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup_Vault"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    }
   ],
   "quote": "a dedicated backup vault encrypted with the shared KMS key"
  },
  {
   "id": "plans",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Plan"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     }
    }
   ],
   "quote": "a corresponding backup plan"
  },
  {
   "id": "plan_vault_bronze",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup"
       }
      ]
     },
     "from_path": [
      "rule",
      "*",
      "target_vault_name"
     ],
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup_Vault"
       }
      ]
     },
     "to_path": [
      "name"
     ]
    }
   ],
   "quote": "a corresponding backup plan"
  },
  {
   "id": "plan_vault_silver",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Plan"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Plan"
       }
      ]
     },
     "from_path": [
      "rule",
      "*",
      "target_vault_name"
     ],
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Vault"
       }
      ]
     },
     "to_path": [
      "name"
     ]
    }
   ],
   "quote": "a corresponding backup plan"
  },
  {
   "id": "plan_vault_gold",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup_Vault"
       }
      ]
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
     },
     "from_path": [
      "rule",
      "*",
      "target_vault_name"
     ],
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup_Vault"
       }
      ]
     },
     "to_path": [
      "name"
     ]
    }
   ],
   "quote": "a corresponding backup plan"
  },
  {
   "id": "plan_vault_premium",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     },
     "from_path": [
      "rule",
      "*",
      "target_vault_name"
     ],
     "to": {
      "types": [
       "aws_backup_vault"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     },
     "to_path": [
      "name"
     ]
    }
   ],
   "quote": "a corresponding backup plan"
  },
  {
   "id": "selections",
   "tier": "core",
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
        "value": "Bronze_Resource_Assignment"
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
        "value": "Silver_Backup_resource"
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
        "value": "Gold_Backup_Select"
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
        "value": "Premium"
       }
      ]
     }
    }
   ],
   "quote": "a resource assignment"
  },
  {
   "id": "selections_plan",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Resource_Assignment"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Bronze_Backup"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_resource"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Silver_Backup_Plan"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup_Select"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_backup_selection"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     },
     "to": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
     }
    }
   ],
   "quote": "a corresponding backup plan, and a resource assignment"
  },
  {
   "id": "selection_tag_bronze",
   "tier": "core",
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
        "value": "Bronze_Resource_Assignment"
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
        "value": "Backup"
       },
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "STRINGEQUALS"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "bronze"
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
        "value": "Bronze_Resource_Assignment"
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
        "value": "aws:ResourceTag/Backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "bronze"
       }
      ]
     }
    }
   ],
   "quote": "filtering resources where the tag key \"Backup\" equals the respective tier name in lowercase (for example \"bronze\") using a STRINGEQUALS comparison"
  },
  {
   "id": "selection_tag_silver",
   "tier": "core",
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
        "value": "Silver_Backup_resource"
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
        "value": "Backup"
       },
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "STRINGEQUALS"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "silver"
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
        "value": "Silver_Backup_resource"
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
        "value": "aws:ResourceTag/Backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "silver"
       }
      ]
     }
    }
   ],
   "quote": "filtering resources where the tag key \"Backup\" equals the respective tier name in lowercase (for example \"bronze\") using a STRINGEQUALS comparison"
  },
  {
   "id": "selection_tag_gold",
   "tier": "core",
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
        "value": "Gold_Backup_Select"
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
        "value": "Backup"
       },
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "STRINGEQUALS"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "gold"
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
        "value": "Gold_Backup_Select"
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
        "value": "aws:ResourceTag/Backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "gold"
       }
      ]
     }
    }
   ],
   "quote": "filtering resources where the tag key \"Backup\" equals the respective tier name in lowercase (for example \"bronze\") using a STRINGEQUALS comparison"
  },
  {
   "id": "selection_tag_premium",
   "tier": "core",
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
        "value": "Premium"
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
        "value": "Backup"
       },
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "STRINGEQUALS"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "premium"
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
        "value": "Premium"
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
        "value": "aws:ResourceTag/Backup"
       },
       {
        "path": [
         "value"
        ],
        "op": "eq",
        "value": "premium"
       }
      ]
     }
    }
   ],
   "quote": "filtering resources where the tag key \"Backup\" equals the respective tier name in lowercase (for example \"bronze\") using a STRINGEQUALS comparison"
  },
  {
   "id": "bronze_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Bronze_Backup"
     }
    ]
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
      "value": "Bronze_Backup_Weekly"
     },
     {
      "path": [
       "schedule"
      ],
      "op": "eq",
      "value": "cron(0 0 ? * FRI *)"
     }
    ]
   },
   "quote": "a weekly rule (\"Bronze_Backup_Weekly\") scheduled at \"cron(0 0 ? * FRI *)\""
  },
  {
   "id": "bronze_ret",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Bronze_Backup"
     }
    ]
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
      "value": "Bronze_Backup_Weekly"
     },
     {
      "path": [
       "lifecycle",
       "*",
       "delete_after"
      ],
      "op": "eq",
      "value": 10
     }
    ]
   },
   "quote": "retaining backups for 10 days"
  },
  {
   "id": "silver_rule",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Silver_Backup_Plan"
     }
    ]
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
      "value": "Silver_Backup_Daily"
     },
     {
      "path": [
       "schedule"
      ],
      "op": "eq",
      "value": "cron(0 5 ? * * *)"
     }
    ]
   },
   "quote": "a daily rule (\"Silver_Backup_Daily\") scheduled at \"cron(0 5 ? * * *)\""
  },
  {
   "id": "silver_ret",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_backup_plan"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Silver_Backup_Plan"
     }
    ]
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
      "value": "Silver_Backup_Daily"
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
   "quote": "retaining backups for 7 days"
  },
  {
   "id": "gold_rules",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Daily_Backup_Rule"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 * * ? *)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Monthly_Backup_Rule"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 1 1/1 ? *)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Yearly_Backup_Rule"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 31 12 ? *)"
       }
      ]
     }
    }
   ],
   "quote": "three rules: a daily rule (\"Gold_Daily_Backup_Rule\") at \"cron(0 0 * * ? *)\""
  },
  {
   "id": "gold_ret",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Daily_Backup_Rule"
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
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Monthly_Backup_Rule"
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
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Gold_Backup"
       }
      ]
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
        "value": "Gold_Yearly_Backup_Rule"
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
     }
    }
   ],
   "quote": "retaining for 31 days, a monthly rule (\"Gold_Monthly_Backup_Rule\") at \"cron(0 0 1 1/1 ? *)\" retaining for 365 days, and a yearly rule (\"Gold_Yearly_Backup_Rule\") at \"cron(0 0 31 12 ? *)\" retaining for 2555 days"
  },
  {
   "id": "premium_rules",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Daily_4Hour_Backup"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0/4 ? * * *)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Daily_Backup"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 * * ? *)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Monthly"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 1 1/1 ? *)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Yearly"
       },
       {
        "path": [
         "schedule"
        ],
        "op": "eq",
        "value": "cron(0 0 31 12 ? *)"
       }
      ]
     }
    }
   ],
   "quote": "a 4-hour rule (\"Premium_Daily_4Hour_Backup\") at \"cron(0 0/4 ? * * *)\""
  },
  {
   "id": "premium_ret",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Daily_4Hour_Backup"
       },
       {
        "path": [
         "lifecycle",
         "*",
         "delete_after"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Daily_Backup"
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
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Monthly"
       },
       {
        "path": [
         "lifecycle",
         "*",
         "delete_after"
        ],
        "op": "eq",
        "value": 365
       },
       {
        "path": [
         "lifecycle",
         "*",
         "cold_storage_after"
        ],
        "op": "eq",
        "value": 15
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_plan"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Premium"
       }
      ]
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
        "value": "Premium_Yearly"
       },
       {
        "path": [
         "lifecycle",
         "*",
         "delete_after"
        ],
        "op": "eq",
        "value": 2555
       },
       {
        "path": [
         "lifecycle",
         "*",
         "cold_storage_after"
        ],
        "op": "eq",
        "value": 15
       }
      ]
     }
    }
   ],
   "quote": "retaining for 1 day, a daily rule (\"Premium_Daily_Backup\") at \"cron(0 0 * * ? *)\" retaining for 31 days, a monthly rule (\"Premium_Monthly\") at \"cron(0 0 1 1/1 ? *)\" transitioning to cold storage after 15 days and deleting after 365 days"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
