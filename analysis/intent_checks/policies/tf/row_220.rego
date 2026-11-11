package intent.tf.row_220

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "agg": {
   "types": [
    "aws_config_configuration_aggregator"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "aggregator",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an AWS Config configuration aggregator",
   "select": "agg"
  },
  {
   "id": "aggregator_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named \"default\"",
   "select": "agg",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "default"
   }
  },
  {
   "id": "all_regions",
   "kind": "any_of",
   "tier": "core",
   "quote": "across all AWS regions",
   "checks": [
    {
     "kind": "attr",
     "select": "agg",
     "cond": {
      "path": [
       "account_aggregation_source",
       "*",
       "all_regions"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "ref",
     "from": "agg",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_regions"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "current_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "for the current AWS account",
   "checks": [
    {
     "kind": "ref",
     "from": "agg",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_caller_identity"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "agg",
     "cond": {
      "path": [
       "account_aggregation_source",
       "*",
       "account_ids",
       "*"
      ],
      "op": "eq",
      "value": "000000000000"
     }
    }
   ],
   "justify": "000000000000 is the plan adapter's account id, i.e. this stack's account"
  },
  {
   "id": "default_tags_terraform",
   "kind": "any_of",
   "tier": "detail",
   "quote": "applying default tags that indicate the stack is managed by Terraform",
   "checks": [
    {
     "kind": "attr",
     "select": "agg",
     "cond": {
      "path": [
       "tags_all"
      ],
      "op": "contains",
      "value": "terraform"
     }
    },
    {
     "kind": "attr",
     "select": "agg",
     "cond": {
      "path": [
       "tags"
      ],
      "op": "contains",
      "value": "terraform"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
