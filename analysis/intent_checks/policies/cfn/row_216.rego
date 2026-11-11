package intent.cfn.row_216

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ks": {
   "types": [
    "AWS::Kinesis::Stream"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "stream",
   "kind": "exists",
   "select": "ks",
   "tier": "core",
   "quote": "creates a Kinesis data stream"
  },
  {
   "id": "one_shard",
   "kind": "attr",
   "select": "ks",
   "cond": {
    "path": [
     "ShardCount"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "configured with a single shard",
   "justify": "a single shard means ShardCount 1"
  },
  {
   "id": "output_stream",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "none_eq",
      "value": "Arn"
     }
    ]
   },
   "to": "ks",
   "tier": "detail",
   "quote": "includes an output that exports the stream's physical ID or name",
   "justify": "physical ID or name is what Ref returns; an Arn output is neither"
  },
  {
   "id": "stream_encryption",
   "kind": "attr",
   "select": "ks",
   "cond": {
    "path": [
     "StreamEncryption",
     "EncryptionType"
    ],
    "op": "eq",
    "value": "KMS"
   },
   "tier": "extra",
   "quote": ""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
