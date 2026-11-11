package intent.tf.row_197

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "enc": {
   "types": [
    "aws_ebs_encryption_by_default"
   ],
   "where": []
  },
  "blk": {
   "types": [
    "aws_ebs_snapshot_block_public_access"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "enc",
   "kind": "exists",
   "select": "enc",
   "tier": "core",
   "quote": "enable default EBS encryption for the region"
  },
  {
   "id": "enc_on",
   "kind": "attr",
   "select": "enc",
   "cond": {
    "path": [
     "enabled"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "enable default EBS encryption for the region (defaulting to true)"
  },
  {
   "id": "blk",
   "kind": "exists",
   "select": "blk",
   "tier": "core",
   "quote": "block public access to EBS snapshots"
  },
  {
   "id": "blk_state",
   "kind": "attr",
   "select": "blk",
   "cond": {
    "path": [
     "state"
    ],
    "op": "eq",
    "value": "block-all-sharing"
   },
   "tier": "core",
   "quote": "a default state of \"block-all-sharing\""
  },
  {
   "id": "params_true",
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
      "value": true
     }
    ]
   },
   "tier": "detail",
   "min": 3,
   "quote": "a global enabling flag that defaults to true",
   "justify": "the global flag and the two specific controls all default to true"
  },
  {
   "id": "param_state",
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
      "value": "block-all-sharing"
     }
    ]
   },
   "tier": "detail",
   "quote": "a default state of \"block-all-sharing\""
  },
  {
   "id": "param_region",
   "kind": "any_of",
   "checks": [
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
        "value": "(?i)region"
       },
       {
        "path": [
         "default"
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
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)region"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": ""
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "unless an optional region variable is explicitly supplied",
   "justify": "an optional override variable has no value by default (null or empty)"
  },
  {
   "id": "gated",
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
      "op": "in",
      "value": [
       "aws_ebs_encryption_by_default",
       "aws_ebs_snapshot_block_public_access"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quantifier": "all",
   "quote": "a global enabling flag that defaults to true"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
