package intent.tf.row_054

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "q": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  },
  "qp": {
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
      "aws_sqs_queue_policy"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "sqs_queue",
   "tier": "core",
   "quote": "creates an Amazon SQS queue",
   "kind": "exists",
   "select": "q"
  },
  {
   "id": "fifo_optional",
   "tier": "core",
   "quote": "optional FIFO queue support",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_sqs_queue"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "fifo_queue"
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
        "value": "(?i)fifo"
       },
       {
        "path": [
         "default"
        ],
        "op": "in",
        "value": [
         false
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "access_policy",
   "tier": "core",
   "quote": "an optional access policy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "qp",
     "to": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
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
         "aws_sqs_queue"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "[{ ]\"policy\": "
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_send_message",
   "tier": "core",
   "quote": "permission to send messages to the queue",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
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
         "data.aws_iam_policy_document",
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sqs:(SendMessage|\\*)"
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
         "default"
        ],
        "op": "regex",
        "value": "(?i)sqs:(SendMessage|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_principal",
   "tier": "detail",
   "quote": "grant a specified AWS principal permission",
   "kind": "exists",
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
       "data.aws_iam_policy_document",
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)principal"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
