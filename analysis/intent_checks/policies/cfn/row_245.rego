package intent.cfn.row_245

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "b": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an Amazon S3 bucket",
   "select": "b"
  },
  {
   "id": "versioning",
   "kind": "attr",
   "tier": "core",
   "quote": "with versioning enabled",
   "select": "b",
   "cond": {
    "path": [
     "VersioningConfiguration",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   }
  },
  {
   "id": "tag_name",
   "kind": "attr",
   "tier": "detail",
   "quote": "tagged with Name \"test\"",
   "select": "b",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Name",
     "value": "test"
    }
   }
  },
  {
   "id": "tag_appname",
   "kind": "attr",
   "tier": "detail",
   "quote": "AppName \"test\"",
   "select": "b",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "AppName",
     "value": "test"
    }
   }
  },
  {
   "id": "tag_env",
   "kind": "attr",
   "tier": "detail",
   "quote": "and Env \"dev\"",
   "select": "b",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "Env",
     "value": "dev"
    }
   }
  },
  {
   "id": "output_bucket_name",
   "kind": "ref",
   "tier": "detail",
   "quote": "exporting the S3 bucket name in the stack outputs",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "b"
  },
  {
   "id": "x_sse",
   "kind": "attr",
   "tier": "extra",
   "select": "b",
   "cond": {
    "path": [
     "BucketEncryption",
     "ServerSideEncryptionConfiguration",
     "*",
     "ServerSideEncryptionByDefault",
     "SSEAlgorithm"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_pab",
   "kind": "attr",
   "tier": "extra",
   "select": "b",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration",
     "BlockPublicAcls"
    ],
    "op": "eq",
    "value": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
