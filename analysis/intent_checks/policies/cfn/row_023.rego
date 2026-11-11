package intent.cfn.row_023

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "efs": {
   "types": [
    "AWS::EFS::FileSystem"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "efs",
   "kind": "exists",
   "select": "efs",
   "tier": "core",
   "quote": "an encrypted EFS file system"
  },
  {
   "id": "encrypted",
   "kind": "attr",
   "select": "efs",
   "cond": {
    "path": [
     "Encrypted"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "an encrypted EFS file system"
  },
  {
   "id": "general_purpose",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "efs",
     "cond": {
      "path": [
       "PerformanceMode"
      ],
      "op": "eq",
      "value": "generalPurpose"
     }
    },
    {
     "kind": "attr",
     "select": "efs",
     "cond": {
      "path": [
       "PerformanceMode"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "for general purpose use",
   "justify": "generalPurpose is the EFS default, so omitting PerformanceMode is also general purpose"
  },
  {
   "id": "backups_disabled",
   "kind": "attr",
   "select": "efs",
   "quantifier": "all",
   "cond": {
    "path": [
     "BackupPolicy",
     "Status"
    ],
    "op": "none_eq",
    "value": "ENABLED"
   },
   "tier": "core",
   "quote": "it should have automated backups disabled",
   "justify": "disabled means the policy is not ENABLED; a file system created through CloudFormation has automatic backups off when BackupPolicy is omitted"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
