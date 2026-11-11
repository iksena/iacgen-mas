package intent.tf.row_077

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
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "lock": {
   "types": [
    "aws_backup_vault_lock_configuration"
   ],
   "where": []
  },
  "plan": {
   "types": [
    "aws_backup_plan"
   ],
   "where": []
  },
  "sel": {
   "types": [
    "aws_backup_selection"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vault",
   "kind": "exists",
   "select": "vault",
   "tier": "core",
   "quote": "a KMS-encrypted, lock-configured backup vault"
  },
  {
   "id": "vault_kms",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "vault",
     "to": "kms"
    },
    {
     "kind": "attr",
     "select": "vault",
     "cond": {
      "path": [
       "kms_key_arn"
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
     }
    }
   ],
   "tier": "core",
   "quote": "a KMS-encrypted, lock-configured backup vault"
  },
  {
   "id": "lock",
   "kind": "exists",
   "select": "lock",
   "tier": "core",
   "quote": "lock-configured backup vault"
  },
  {
   "id": "lock_on_vault",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "lock",
     "to": "vault"
    },
    {
     "kind": "join",
     "from": "lock",
     "from_path": [
      "backup_vault_name"
     ],
     "to": "vault",
     "to_path": [
      "name"
     ]
    }
   ],
   "tier": "core",
   "quote": "lock-configured backup vault"
  },
  {
   "id": "lock_min7",
   "kind": "attr",
   "select": "lock",
   "cond": {
    "path": [
     "min_retention_days"
    ],
    "op": "eq",
    "value": 7
   },
   "tier": "core",
   "quote": "enforcing retention between 7 and 90 days"
  },
  {
   "id": "lock_max90",
   "kind": "attr",
   "select": "lock",
   "cond": {
    "path": [
     "max_retention_days"
    ],
    "op": "eq",
    "value": 90
   },
   "tier": "core",
   "quote": "enforcing retention between 7 and 90 days"
  },
  {
   "id": "plan",
   "kind": "exists",
   "select": "plan",
   "tier": "core",
   "quote": "a backup plan with a scheduled rule"
  },
  {
   "id": "rule_schedule",
   "kind": "attr",
   "select": "plan",
   "cond": {
    "path": [
     "rule",
     "*",
     "schedule"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "a scheduled rule"
  },
  {
   "id": "rule_targets_vault",
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
      "rule",
      "*",
      "target_vault_name"
     ],
     "to": "vault",
     "to_path": [
      "name"
     ]
    }
   ],
   "tier": "core",
   "quote": "a scheduled rule targeting that vault"
  },
  {
   "id": "selection",
   "kind": "exists",
   "select": "sel",
   "tier": "core",
   "quote": "a backup selection"
  },
  {
   "id": "selection_plan",
   "kind": "ref",
   "from": "sel",
   "to": "plan",
   "tier": "detail",
   "quote": "a backup selection that automatically backs up all resources"
  },
  {
   "id": "selection_tag",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sel",
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
        "op": "regex",
        "value": "(?i)^aws:ResourceTag/benchmark-backup$"
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
    },
    {
     "kind": "attr",
     "select": "sel",
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
        "value": "benchmark-backup"
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
    }
   ],
   "tier": "core",
   "quote": "tagged with a \"benchmark-backup\" tag set to \"true\""
  },
  {
   "id": "selection_all_resources",
   "tier": "core",
   "quote": "automatically backs up all resources",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "selection_tag",
       "*"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "sel",
     "cond": {
      "path": [
       "resources",
       "*"
      ],
      "op": "eq",
      "value": "*"
     }
    }
   ],
   "justify": "selecting by tag alone, or the wildcard resource list plus a tag condition, covers all resources carrying the tag"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  },
  {
   "id": "lock_grace",
   "kind": "attr",
   "select": "lock",
   "cond": {
    "path": [
     "changeable_for_days"
    ],
    "op": "present"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
