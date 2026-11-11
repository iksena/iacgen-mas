package intent.tf.row_347

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fs": {
   "types": [
    "aws_efs_file_system"
   ],
   "where": []
  },
  "bp": {
   "types": [
    "aws_efs_backup_policy"
   ],
   "where": []
  },
  "mt": {
   "types": [
    "aws_efs_mount_target"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "aws_efs_file_system_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "efs",
   "kind": "exists",
   "select": "fs",
   "tier": "core",
   "quote": "creates an encrypted Amazon EFS file system"
  },
  {
   "id": "encrypted",
   "kind": "attr",
   "select": "fs",
   "tier": "core",
   "quote": "an encrypted Amazon EFS file system",
   "cond": {
    "path": [
     "encrypted"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "perf",
   "kind": "attr",
   "select": "fs",
   "tier": "core",
   "quote": "using the general purpose performance mode",
   "cond": {
    "path": [
     "performance_mode"
    ],
    "op": "regex",
    "value": "(?i)^general_?purpose$"
   }
  },
  {
   "id": "throughput",
   "kind": "attr",
   "select": "fs",
   "tier": "core",
   "quote": "bursting throughput mode",
   "cond": {
    "path": [
     "throughput_mode"
    ],
    "op": "eq",
    "value": "bursting"
   }
  },
  {
   "id": "default_key",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the default AWS-managed encryption key",
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
        "value": "aws_efs_file_system"
       },
       {
        "path": [
         "properties",
         "kms_key_id"
        ],
        "op": "absent"
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
        "value": "aws_efs_file_system"
       },
       {
        "path": [
         "properties",
         "kms_key_id"
        ],
        "op": "regex",
        "value": "(?i)alias/aws/elasticfilesystem"
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
        "value": "aws_efs_file_system"
       },
       {
        "path": [
         "properties",
         "kms_key_id"
        ],
        "op": "regex",
        "value": "^\\$\\{var\\.[A-Za-z0-9_]+\\}$"
       }
      ]
     }
    }
   ],
   "justify": "an unset kms_key_id (omitted, or a variable reference) means the default AWS-managed EFS key"
  },
  {
   "id": "creation_token_generated",
   "kind": "attr",
   "select": "fs",
   "tier": "detail",
   "quote": "a Terraform-generated creation token",
   "cond": {
    "path": [
     "creation_token"
    ],
    "op": "absent"
   }
  },
  {
   "id": "no_mt_sg_policy_by_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "No mount targets, security group, file system policy, or lifecycle transitions should be created by default",
   "select": {
    "types": [
     "aws_efs_file_system",
     "aws_efs_mount_target",
     "aws_security_group",
     "aws_efs_file_system_policy"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "justify": "the one file system the prompt asks for is the only resource among these types; mount targets, security groups and file system policies must number zero by default"
  },
  {
   "id": "no_lifecycle_transitions",
   "kind": "exists",
   "tier": "detail",
   "quote": "No mount targets, security group, file system policy, or lifecycle transitions should be created by default",
   "select": {
    "types": [
     "aws_efs_file_system"
    ],
    "where": [
     {
      "path": [
       "lifecycle_policy",
       "*"
      ],
      "op": "absent"
     }
    ]
   }
  },
  {
   "id": "backup_policy",
   "kind": "exists",
   "select": "bp",
   "tier": "core",
   "quote": "attaches a backup policy with automatic backups enabled"
  },
  {
   "id": "backup_enabled",
   "kind": "attr",
   "select": "bp",
   "tier": "core",
   "quote": "automatic backups enabled",
   "cond": {
    "path": [
     "backup_policy",
     "*",
     "status"
    ],
    "op": "eq",
    "value": "ENABLED"
   }
  },
  {
   "id": "backup_on_fs",
   "kind": "ref",
   "from": "bp",
   "to": "fs",
   "tier": "detail",
   "quote": "attaches a backup policy"
  },
  {
   "id": "extra_type_aws_efs_file_system_policy",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_efs_file_system_policy"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_efs_mount_target",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_efs_mount_target"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_security_group",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_security_group"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
