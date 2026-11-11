package intent.tf.row_330

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "queue": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "aggregation-lambda-dead-letter-queue"
    }
   ]
  },
  "key": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_kms_alias"
    },
    {
     "path": [
      "properties",
      "target_key_id"
     ],
     "op": "contains",
     "value": "aws_kms_key."
    }
   ]
  },
  "any_queue": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "queue_named",
   "kind": "exists",
   "tier": "core",
   "quote": "an SQS dead-letter queue named \"aggregation-lambda-dead-letter-queue\"",
   "select": "queue"
  },
  {
   "id": "retention_14d",
   "kind": "attr",
   "tier": "core",
   "quote": "a 14-day message retention period",
   "justify": "14 days = 1209600 seconds",
   "select": "any_queue",
   "cond": {
    "path": [
     "message_retention_seconds"
    ],
    "op": "eq",
    "value": 1209600
   }
  },
  {
   "id": "cmk_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "a new customer-managed KMS key",
   "select": "key"
  },
  {
   "id": "key_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "key rotation enabled",
   "select": "key",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "queue_uses_key",
   "kind": "any_of",
   "tier": "core",
   "quote": "encrypted with a new customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": "any_queue",
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "any_queue",
     "to": "alias"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
