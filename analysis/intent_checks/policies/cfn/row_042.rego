package intent.cfn.row_042

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "t": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "pols": {
   "types": [
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Policy"
   ],
   "where": []
  },
  "mp": {
   "types": [
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "params": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "table",
   "tier": "core",
   "quote": "creates an idempotency store using DynamoDB",
   "kind": "exists",
   "select": "t"
  },
  {
   "id": "hash_key",
   "tier": "core",
   "quote": "a composite primary key with a partition key and sort key",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "KeySchema",
     "*",
     "KeyType"
    ],
    "op": "eq",
    "value": "HASH"
   },
   "justify": "partition key is the HASH key"
  },
  {
   "id": "range_key",
   "tier": "core",
   "quote": "a composite primary key with a partition key and sort key",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "KeySchema",
     "*",
     "KeyType"
    ],
    "op": "eq",
    "value": "RANGE"
   },
   "justify": "sort key is the RANGE key"
  },
  {
   "id": "ttl",
   "tier": "core",
   "quote": "enable Time-to-Live",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "TimeToLiveSpecification",
     "Enabled"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "ttl_default",
   "tier": "detail",
   "quote": "a configurable default of 7 days",
   "kind": "attr",
   "select": "params",
   "cond": {
    "path": [
     "default"
    ],
    "op": "in",
    "value": [
     7,
     604800
    ]
   },
   "justify": "7 days is the stated TTL default, in days or as 604800 seconds"
  },
  {
   "id": "pitr",
   "tier": "core",
   "quote": "support Point-in-Time Recovery enabled by default",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "PointInTimeRecoverySpecification",
     "PointInTimeRecoveryEnabled"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "policy",
   "tier": "core",
   "quote": "a managed IAM policy",
   "kind": "exists",
   "select": "mp"
  },
  {
   "id": "policy_table",
   "tier": "core",
   "quote": "grants Lambda and Step Functions read/write access to the table",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "pols",
     "to": "t"
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Resource",
       "*"
      ],
      "op": "regex",
      "value": ":table/"
     }
    }
   ],
   "justify": "a table ARN built from the table's name is the other way to name the table"
  },
  {
   "id": "policy_read",
   "tier": "detail",
   "quote": "read/write access to the table",
   "kind": "any_of",
   "justify": "read access implies an item read action",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:GetItem"
     }
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:Query"
     }
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:BatchGetItem"
     }
    }
   ]
  },
  {
   "id": "policy_write",
   "tier": "detail",
   "quote": "read/write access to the table",
   "kind": "any_of",
   "justify": "write access implies an item write action",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:PutItem"
     }
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:UpdateItem"
     }
    },
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:BatchWriteItem"
     }
    }
   ]
  },
  {
   "id": "prefix_param",
   "tier": "core",
   "quote": "a project prefix parameter (default \"fsxn-s3ap\")",
   "kind": "attr",
   "select": "params",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "fsxn-s3ap"
   }
  },
  {
   "id": "prefix_naming",
   "tier": "detail",
   "quote": "for naming resources",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "regex",
    "value": "^fsxn-s3ap"
   }
  },
  {
   "id": "billing",
   "tier": "extra",
   "kind": "attr",
   "select": "t",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   }
  },
  {
   "id": "policy_query",
   "tier": "extra",
   "kind": "attr",
   "select": "pols",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "dynamodb:Query"
   }
  },
  {
   "id": "policy_delete",
   "tier": "extra",
   "kind": "attr",
   "select": "pols",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "dynamodb:DeleteItem"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
