package intent.tf.row_198

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "user",
   "kind": "exists",
   "select": "user",
   "tier": "core",
   "quote": "an IAM deployment user"
  },
  {
   "id": "user_name",
   "kind": "attr",
   "select": "user",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "DeploymentUser"
   },
   "tier": "core",
   "quote": "a configurable username defaulting to \"DeploymentUser\""
  },
  {
   "id": "param_username",
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
      "op": "eq",
      "value": "DeploymentUser"
     }
    ]
   },
   "tier": "detail",
   "quote": "a configurable username defaulting to \"DeploymentUser\""
  },
  {
   "id": "param_tags",
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
      "value": "(?i)tags"
     }
    ]
   },
   "tier": "detail",
   "quote": "support optional resource tags"
  },
  {
   "id": "param_bucket_arns",
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
      "value": "(?i)(s3|bucket)"
     }
    ]
   },
   "tier": "detail",
   "quote": "when a list of target bucket ARNs is provided"
  },
  {
   "id": "param_s3_paths",
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
      "value": "(?i)path"
     }
    ]
   },
   "tier": "detail",
   "quote": "mapped to customizable bucket sub-paths (defaulting to wildcards)"
  },
  {
   "id": "param_lambda_arns",
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
      "value": "(?i)(lambda|function)"
     }
    ]
   },
   "tier": "detail",
   "quote": "when function ARNs are provided"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
