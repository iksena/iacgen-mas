package intent.tf.row_067

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "raw_table",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "quote": "two DynamoDB tables named \"raw_metrics\" and \"aggregate_metrics\""
  },
  {
   "id": "agg_table",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "quote": "two DynamoDB tables named \"raw_metrics\" and \"aggregate_metrics\""
  },
  {
   "id": "raw_on_demand",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "billing_mode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "quote": "Both tables must utilize on-demand (PAY_PER_REQUEST) billing"
  },
  {
   "id": "agg_on_demand",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "billing_mode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "quote": "Both tables must utilize on-demand (PAY_PER_REQUEST) billing"
  },
  {
   "id": "raw_sse",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "server_side_encryption",
     "*",
     "enabled"
    ],
    "op": "truthy"
   },
   "quote": "have server-side encryption enabled"
  },
  {
   "id": "agg_sse",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "server_side_encryption",
     "*",
     "enabled"
    ],
    "op": "truthy"
   },
   "quote": "have server-side encryption enabled"
  },
  {
   "id": "raw_hash_key",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "hash_key"
    ],
    "op": "eq",
    "value": "uuid"
   },
   "quote": "define a string hash key named \"uuid\""
  },
  {
   "id": "raw_hash_key_type",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "attribute",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "uuid"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "define a string hash key named \"uuid\""
  },
  {
   "id": "raw_stream",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "stream_enabled"
    ],
    "op": "truthy"
   },
   "quote": "enable a DynamoDB stream"
  },
  {
   "id": "raw_stream_view",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "stream_view_type"
    ],
    "op": "eq",
    "value": "NEW_IMAGE"
   },
   "quote": "configured for \"NEW_IMAGE\" view types"
  },
  {
   "id": "raw_ttl_attr",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "raw_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "ttl",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "attribute_name"
      ],
      "op": "eq",
      "value": "expdate"
     },
     {
      "path": [
       "enabled"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "a time-to-live (TTL) configuration enabled on an attribute named \"expdate\""
  },
  {
   "id": "agg_hash_key",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "hash_key"
    ],
    "op": "eq",
    "value": "pk"
   },
   "quote": "a string hash key named \"pk\""
  },
  {
   "id": "agg_hash_key_type",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "attribute",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "pk"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "a string hash key named \"pk\""
  },
  {
   "id": "agg_range_key",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "range_key"
    ],
    "op": "eq",
    "value": "sk"
   },
   "quote": "a string range key named \"sk\""
  },
  {
   "id": "agg_range_key_type",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "attribute",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "sk"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "a string range key named \"sk\""
  },
  {
   "id": "agg_pitr",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "point_in_time_recovery",
     "*",
     "enabled"
    ],
    "op": "truthy"
   },
   "quote": "enable point-in-time recovery"
  },
  {
   "id": "agg_gsi",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "global_secondary_index",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "IdentifierIndex"
     },
     {
      "path": [
       "projection_type"
      ],
      "op": "eq",
      "value": "ALL"
     },
     {
      "path": [
       "hash_key"
      ],
      "op": "eq",
      "value": "identifier"
     }
    ]
   },
   "quote": "define a global secondary index named \"IdentifierIndex\" with \"ALL\" projected attributes using a string hash key named \"identifier\""
  },
  {
   "id": "agg_gsi_key_type",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "aggregate_metrics"
     }
    ]
   },
   "cond": {
    "path": [
     "attribute",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "identifier"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "quote": "using a string hash key named \"identifier\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
