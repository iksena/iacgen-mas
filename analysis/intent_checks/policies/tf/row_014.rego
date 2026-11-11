package intent.tf.row_014

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lg": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": []
  },
  "pet": {
   "types": [
    "random_pet"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "creates an Amazon CloudWatch log group"
  },
  {
   "id": "log_group_prefix",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^log-group-"
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
        "value": "aws_cloudwatch_log_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "^log-group-"
     }
    },
    {
     "kind": "ref",
     "from": "lg",
     "to": {
      "types": [
       "random_pet"
      ],
      "where": [
       {
        "path": [
         "prefix"
        ],
        "op": "regex",
        "value": "^log-group-?$"
       },
       {
        "path": [
         "separator"
        ],
        "op": "eq",
        "value": "-"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "The log group name must start with the prefix \"log-group-\""
  },
  {
   "id": "random_pet",
   "kind": "exists",
   "select": "pet",
   "tier": "core",
   "quote": "random two-word pet name identifier"
  },
  {
   "id": "pet_two_words",
   "kind": "attr",
   "select": "pet",
   "cond": {
    "path": [
     "length"
    ],
    "op": "eq",
    "value": 2
   },
   "tier": "core",
   "quote": "random two-word pet name identifier",
   "justify": "two-word means length 2"
  },
  {
   "id": "name_uses_pet",
   "kind": "ref",
   "from": "lg",
   "to": "pet",
   "tier": "core",
   "quote": "appended with a random two-word pet name identifier"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
