package intent.cfn.row_012

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "AWS::DLM::LifecyclePolicy"
   ],
   "where": []
  },
  "dlm_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "dlm.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "dlm_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "creates an IAM role for the DLM service"
  },
  {
   "id": "role_trust_dlm",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "dlm.amazonaws.com"
   },
   "tier": "core",
   "quote": "an IAM role for the DLM service"
  },
  {
   "id": "lifecycle_policy",
   "kind": "exists",
   "select": "pol",
   "tier": "core",
   "quote": "a lifecycle policy to take daily snapshots of any EBS volumes"
  },
  {
   "id": "policy_uses_role",
   "kind": "ref",
   "from": "pol",
   "to": "dlm_role",
   "tier": "core",
   "quote": "an IAM role for the DLM service and a lifecycle policy"
  },
  {
   "id": "target_tag",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "PolicyDetails",
     "TargetTags",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Key"
      ],
      "op": "eq",
      "value": "TeemDLM"
     },
     {
      "path": [
       "Value"
      ],
      "op": "eq",
      "value": "daily"
     }
    ]
   },
   "tier": "core",
   "quote": "tagged with the key \"TeemDLM\" and value \"daily\""
  },
  {
   "id": "resource_type_volume",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "PolicyDetails",
     "ResourceTypes",
     "*"
    ],
    "op": "eq",
    "value": "VOLUME"
   },
   "tier": "core",
   "quote": "EBS volumes tagged"
  },
  {
   "id": "every_24h_at_0100",
   "kind": "any_of",
   "tier": "core",
   "quote": "snapshots taken every 24 hours at 1:00 UTC",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "PolicyDetails",
       "Schedules",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "CreateRule",
         "Interval"
        ],
        "op": "eq",
        "value": 24
       },
       {
        "path": [
         "CreateRule",
         "IntervalUnit"
        ],
        "op": "eq",
        "value": "HOURS"
       },
       {
        "path": [
         "CreateRule",
         "Times",
         "*"
        ],
        "op": "regex",
        "value": "^0?1:00$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [
       "PolicyDetails",
       "Schedules",
       "*",
       "CreateRule",
       "CronExpression"
      ],
      "op": "regex",
      "value": "^cron\\(0?0 0?1 (\\* \\* \\?|\\? \\* \\*) \\*\\)$"
     }
    }
   ],
   "justify": "24 hours and 1:00 are stated; the equivalent daily cron at 01:00 is accepted"
  },
  {
   "id": "retain_7",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "RetainRule",
     "Count"
    ],
    "op": "eq",
    "value": 7
   },
   "tier": "core",
   "quote": "retaining the last 7 copies"
  },
  {
   "id": "copy_tags",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "PolicyDetails",
     "Schedules",
     "*",
     "CopyTags"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "automatically copying all volume tags to the snapshots"
  },
  {
   "id": "policy_enabled",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "State"
    ],
    "op": "none_eq",
    "value": "DISABLED"
   },
   "tier": "detail",
   "quote": "a lifecycle policy to take daily snapshots",
   "justify": "a disabled policy takes no snapshots; omitted State is not a violation"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
