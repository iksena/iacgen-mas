package intent.tf.row_332

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "p": {
   "types": [
    "aws_sns_sms_preferences"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "prefs_exist",
   "kind": "exists",
   "tier": "core",
   "quote": "account-level Amazon SNS SMS messaging preferences",
   "select": "p"
  },
  {
   "id": "sms_type",
   "kind": "attr",
   "tier": "core",
   "quote": "default SMS type to \"Transactional\"",
   "select": "p",
   "cond": {
    "path": [
     "default_sms_type"
    ],
    "op": "eq",
    "value": "Transactional"
   }
  },
  {
   "id": "sampling_zero",
   "kind": "attr",
   "tier": "core",
   "quote": "delivery-status success sampling rate to 0",
   "select": "p",
   "cond": {
    "path": [
     "delivery_status_success_sampling_rate"
    ],
    "op": "eq",
    "value": 0
   }
  },
  {
   "id": "unset_by_default",
   "kind": "all_of",
   "tier": "detail",
   "quote": "leaving the sender ID, monthly spend limit, delivery-status IAM role, and usage-report bucket unset by default",
   "checks": [
    {
     "kind": "attr",
     "select": "p",
     "cond": {
      "path": [
       "default_sender_id"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "p",
     "cond": {
      "path": [
       "monthly_spend_limit"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "p",
     "cond": {
      "path": [
       "delivery_status_iam_role_arn"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "p",
     "cond": {
      "path": [
       "usage_report_s3_bucket"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "has_output",
   "kind": "any_of",
   "tier": "detail",
   "quote": "outputs the configured preference values",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": "p"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)transactional"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
