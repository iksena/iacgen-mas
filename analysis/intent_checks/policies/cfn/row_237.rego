package intent.cfn.row_237

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
   "quote": "a standard private S3 bucket",
   "select": "b"
  },
  {
   "id": "bucket_private",
   "kind": "exists",
   "tier": "core",
   "quote": "private S3 bucket",
   "justify": "private means no public ACL and no public access block setting switched off; a bucket that sets neither is private by S3 default",
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
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
