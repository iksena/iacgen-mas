package intent.tf.row_319

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rule": {
   "types": [
    "aws_config_config_rule"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "config_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an AWS Config managed rule",
   "select": "rule"
  },
  {
   "id": "rule_owner_aws",
   "kind": "attr",
   "tier": "core",
   "quote": "AWS Config managed rule",
   "select": "rule",
   "cond": {
    "path": [
     "source",
     "*",
     "owner"
    ],
    "op": "eq",
    "value": "AWS"
   }
  },
  {
   "id": "rule_acm_expiration",
   "kind": "attr",
   "tier": "core",
   "quote": "checks whether ACM certificates in the account are close to expiring",
   "select": "rule",
   "cond": {
    "path": [
     "source",
     "*",
     "source_identifier"
    ],
    "op": "regex",
    "value": "(?i)ACM_CERTIFICATE_EXPIRATION"
   },
   "justify": "the AWS managed rule for ACM certificates nearing expiry is ACM_CERTIFICATE_EXPIRATION_CHECK"
  },
  {
   "id": "rule_toggle",
   "kind": "exists",
   "tier": "detail",
   "quote": "enabled by default",
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
      "value": "aws_config_config_rule"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "gate"
      ],
      "op": "regex",
      "value": "(var|local)\\."
     }
    ]
   },
   "justify": "'enabled by default' implies the rule's count depends on an input that can switch it off"
  },
  {
   "id": "name_prefix_optional",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with an optional name prefix",
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
        "value": "aws_config_config_rule"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "(?i)prefix"
       }
      ]
     }
    },
    {
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
        "value": "(?i)prefix"
       },
       {
        "path": [
         "default"
        ],
        "op": "in",
        "value": [
         "",
         null
        ]
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
