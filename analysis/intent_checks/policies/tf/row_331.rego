package intent.tf.row_331

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "q": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "queue_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "a standard (non-FIFO) Amazon SQS queue",
   "select": "q"
  },
  {
   "id": "not_fifo",
   "kind": "any_of",
   "tier": "core",
   "quote": "standard (non-FIFO)",
   "checks": [
    {
     "kind": "attr",
     "select": "q",
     "cond": {
      "path": [
       "fifo_queue"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": "q",
     "cond": {
      "path": [
       "fifo_queue"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "auto_name",
   "kind": "attr",
   "tier": "core",
   "quote": "an auto-generated name",
   "justify": "auto-generated means no explicit name is set",
   "select": "q",
   "cond": {
    "path": [
     "name"
    ],
    "op": "absent"
   }
  },
  {
   "id": "visibility_30",
   "kind": "attr",
   "tier": "core",
   "quote": "a visibility timeout of 30 seconds",
   "select": "q",
   "cond": {
    "path": [
     "visibility_timeout_seconds"
    ],
    "op": "eq",
    "value": 30
   }
  },
  {
   "id": "retention",
   "kind": "attr",
   "tier": "core",
   "quote": "a message retention period of 345600 seconds",
   "select": "q",
   "cond": {
    "path": [
     "message_retention_seconds"
    ],
    "op": "eq",
    "value": 345600
   }
  },
  {
   "id": "max_size",
   "kind": "attr",
   "tier": "core",
   "quote": "a maximum message size of 262144 bytes",
   "select": "q",
   "cond": {
    "path": [
     "max_message_size"
    ],
    "op": "eq",
    "value": 262144
   }
  },
  {
   "id": "no_delay",
   "kind": "attr",
   "tier": "core",
   "quote": "no delivery delay",
   "justify": "no delay = 0 seconds",
   "select": "q",
   "cond": {
    "path": [
     "delay_seconds"
    ],
    "op": "eq",
    "value": 0
   }
  },
  {
   "id": "no_long_poll",
   "kind": "attr",
   "tier": "core",
   "quote": "no long-polling wait time",
   "justify": "no wait = 0 seconds",
   "select": "q",
   "cond": {
    "path": [
     "receive_wait_time_seconds"
    ],
    "op": "eq",
    "value": 0
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
