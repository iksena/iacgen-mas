package intent.cfn.row_222

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bk": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "tbl": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_buckets",
   "kind": "exists",
   "select": "bk",
   "tier": "core",
   "quote": "two private S3 buckets",
   "min": 2
  },
  {
   "id": "buckets_private",
   "kind": "exists",
   "min": 2,
   "select": {
    "types": [
     "AWS::S3::Bucket"
    ],
    "where": [
     {
      "path": [
       "AccessControl"
      ],
      "op": "none_eq",
      "value": "PublicRead"
     },
     {
      "path": [
       "AccessControl"
      ],
      "op": "none_eq",
      "value": "PublicReadWrite"
     },
     {
      "path": [
       "AccessControl"
      ],
      "op": "none_eq",
      "value": "AuthenticatedRead"
     },
     {
      "path": [
       "PublicAccessBlockConfiguration",
       "BlockPublicAcls"
      ],
      "op": "none_eq",
      "value": false
     },
     {
      "path": [
       "PublicAccessBlockConfiguration",
       "BlockPublicPolicy"
      ],
      "op": "none_eq",
      "value": false
     },
     {
      "path": [
       "PublicAccessBlockConfiguration",
       "IgnorePublicAcls"
      ],
      "op": "none_eq",
      "value": false
     },
     {
      "path": [
       "PublicAccessBlockConfiguration",
       "RestrictPublicBuckets"
      ],
      "op": "none_eq",
      "value": false
     }
    ]
   },
   "tier": "core",
   "quote": "two private S3 buckets",
   "justify": "private: no public canned ACL and no public access block switched off; omitting both is private by default"
  },
  {
   "id": "table",
   "kind": "exists",
   "select": "tbl",
   "tier": "core",
   "quote": "a DynamoDB table"
  },
  {
   "id": "table_name",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "eq",
    "value": "video-metadata"
   },
   "tier": "core",
   "quote": "a DynamoDB table named \"video-metadata\""
  },
  {
   "id": "partition_key",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "KeySchema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "id"
     },
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "HASH"
     }
    ]
   },
   "tier": "core",
   "quote": "string partition key \"id\"",
   "justify": "partition key = HASH key type"
  },
  {
   "id": "partition_key_string",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "AttributeDefinitions",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "id"
     },
     {
      "path": [
       "AttributeType"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   },
   "tier": "core",
   "quote": "string partition key \"id\""
  },
  {
   "id": "read_capacity",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "ReadCapacityUnits"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "1 read capacity unit"
  },
  {
   "id": "write_capacity",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "WriteCapacityUnits"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "1 write capacity unit"
  },
  {
   "id": "stream_new_image",
   "kind": "attr",
   "select": "tbl",
   "cond": {
    "path": [
     "StreamSpecification",
     "StreamViewType"
    ],
    "op": "eq",
    "value": "NEW_IMAGE"
   },
   "tier": "core",
   "quote": "a DynamoDB stream enabled with a \"NEW_IMAGE\" view type"
  },
  {
   "id": "export_assets_bucket",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "eq",
      "value": "Assets-AssetsBucket"
     },
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "absent"
     }
    ]
   },
   "to": "bk",
   "tier": "detail",
   "quote": "exporting the reference to the main assets bucket as \"Assets-AssetsBucket\""
  },
  {
   "id": "bucket_encryption",
   "kind": "attr",
   "select": "bk",
   "cond": {
    "path": [
     "BucketEncryption"
    ],
    "op": "present"
   },
   "tier": "extra",
   "quote": "",
   "quantifier": "all"
  },
  {
   "id": "bucket_public_block",
   "kind": "attr",
   "select": "bk",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration",
     "BlockPublicPolicy"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "extra",
   "quote": "",
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
