# GENERATED from specs/tf/row_343.json by intent_checks/build.py -- do not edit.
package intent.tf.row_343

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "CloudHealth-IAM-Role"
    }
   ]
  },
  "policy": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "CloudHealth-IAM-Role"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_named",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "a cross-account IAM role named \"CloudHealth-IAM-Role\""
  },
  {
   "id": "trust_cross_account",
   "kind": "attr",
   "select": "role",
   "tier": "core",
   "quote": "that the CloudHealth SaaS platform's AWS account can assume",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "sts:AssumeRole"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "\"AWS\"\\s*:"
     }
    ]
   }
  },
  {
   "id": "trust_external_id",
   "kind": "attr",
   "select": "role",
   "tier": "core",
   "quote": "using an external ID condition",
   "cond": {
    "path": [
     "assume_role_policy"
    ],
    "op": "contains",
    "value": "sts:ExternalId"
   }
  },
  {
   "id": "policy_same_name",
   "kind": "exists",
   "select": "policy",
   "tier": "core",
   "quote": "a customer-managed IAM policy of the same name"
  },
  {
   "id": "policy_read_only_actions",
   "kind": "attr",
   "select": "policy",
   "tier": "detail",
   "quote": "granting broad read-only describe, list and get permissions across AWS services",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":Describe"
     },
     {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":List"
     },
     {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":Get"
     }
    ]
   }
  },
  {
   "id": "policy_attached_to_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to the role",
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
         "role"
        ],
        "op": "eq",
        "value": "CloudHealth-IAM-Role"
       }
      ]
     },
     "to": "policy"
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
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "CloudHealth-IAM-Role"
       }
      ]
     },
     "to": "policy"
    },
    {
     "kind": "ref",
     "from": "role",
     "to": "policy"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
