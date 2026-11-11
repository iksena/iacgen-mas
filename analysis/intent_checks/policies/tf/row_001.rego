package intent.tf.row_001

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "framework_exists",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_backup_framework"
    ],
    "where": []
   },
   "quote": "creates an AWS Backup framework"
  },
  {
   "id": "framework_name",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_backup_framework"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "benchmark"
   },
   "quote": "configured using a variable that defaults to \"benchmark\"",
   "justify": "name set to the stated variable default benchmark"
  },
  {
   "id": "framework_description",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_backup_framework"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "benchmark"
   },
   "quote": "The framework's name and description should be configured using a variable that defaults to \"benchmark\"",
   "justify": "description set to the stated variable default benchmark"
  },
  {
   "id": "var_default_benchmark",
   "kind": "exists",
   "tier": "detail",
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
      "value": "benchmark"
     }
    ]
   },
   "quote": "a variable that defaults to \"benchmark\""
  },
  {
   "id": "control_name",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_backup_framework"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "control",
     "*",
     "name"
    ],
    "op": "eq",
    "value": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
   },
   "quote": "a control named \"BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN\""
  },
  {
   "id": "control_scope_ebs",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_backup_framework"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "control",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
     },
     {
      "path": [
       "scope",
       "*",
       "compliance_resource_types"
      ],
      "op": "len_eq",
      "value": 1
     },
     {
      "path": [
       "scope",
       "*",
       "compliance_resource_types",
       "*"
      ],
      "op": "eq",
      "value": "EBS"
     }
    ]
   },
   "quote": "scoped strictly to EBS compliance resource types",
   "justify": "'strictly to EBS' means the control's resource-type list is exactly [EBS]"
  },
  {
   "id": "null_resource_exists",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "null_resource",
     "terraform_data"
    ],
    "where": []
   },
   "quote": "a basic null resource deployed within the same stack"
  },
  {
   "id": "tag_value_null_id",
   "kind": "attr",
   "tier": "core",
   "quote": "set the tag's value to the generated ID of a basic null resource",
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
      "value": "aws_backup_framework"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "tags"
    ],
    "op": "regex",
    "value": "\\$\\{(null_resource|terraform_data)\\.[A-Za-z0-9_-]+\\.id\\}"
   }
  },
  {
   "id": "tag_key_variable",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_backup_framework"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "BenchmarkTag"
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
        "value": "aws_backup_framework"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "tags"
      ],
      "op": "regex",
      "value": "(?i)(var\\.[a-z0-9_-]+|benchmarktag)\"?\\s*:\\s*\"?\\$\\{(null_resource|terraform_data)\\."
     }
    }
   ],
   "quote": "tag the backup framework using a variable for the tag key that defaults to \"BenchmarkTag\""
  },
  {
   "id": "var_default_tagkey",
   "kind": "exists",
   "tier": "detail",
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
      "value": "BenchmarkTag"
     }
    ]
   },
   "quote": "a variable for the tag key that defaults to \"BenchmarkTag\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
