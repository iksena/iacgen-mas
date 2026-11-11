package intent.cfn.row_264

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "tables": {
   "types": [
    "AWS::DynamoDB::Table",
    "AWS::DynamoDB::GlobalTable"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "six_tables",
   "kind": "exists",
   "tier": "core",
   "select": "tables",
   "min": 6,
   "max": 6,
   "quote": "consisting of six on-demand tables"
  },
  {
   "id": "pay_per_request",
   "kind": "attr",
   "tier": "core",
   "select": "tables",
   "quantifier": "all",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "quote": "pay-per-request billing rather than provisioned capacity"
  },
  {
   "id": "prefix",
   "kind": "attr",
   "tier": "core",
   "select": "tables",
   "quantifier": "all",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "regex",
    "value": "^socless_"
   },
   "quote": "use the socless_ naming prefix"
  },
  {
   "id": "k_event",
   "kind": "exists",
   "tier": "core",
   "quote": "an events table keyed on an event identifier",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)event"
     },
     {
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
        "op": "regex",
        "value": "(?i)^(event[-_]?)?(id|identifier|uuid|guid)$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it, and on such a table a bare id is that entity identifier"
  },
  {
   "id": "k_exec",
   "kind": "exists",
   "tier": "core",
   "quote": "an execution results table keyed on an execution identifier",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)execution|result"
     },
     {
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
        "op": "regex",
        "value": "(?i)^(execution[-_]?)?(id|identifier|uuid|guid)$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it, and on such a table a bare id is that entity identifier"
  },
  {
   "id": "k_msg",
   "kind": "exists",
   "tier": "core",
   "quote": "a message responses table keyed on a message identifier",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)message|response"
     },
     {
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
        "op": "regex",
        "value": "(?i)^(message[-_]?)?(id|identifier|uuid|guid)$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it, and on such a table a bare id is that entity identifier"
  },
  {
   "id": "k_playbook",
   "kind": "exists",
   "tier": "core",
   "quote": "a playbooks table keyed on the state machine name",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)playbook"
     },
     {
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
        "op": "regex",
        "value": "(?i)^state[-_]?machine([-_]?name)?$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it"
  },
  {
   "id": "k_mapping",
   "kind": "exists",
   "tier": "core",
   "quote": "a custom mappings table keyed on a lookup key",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)mapping|lookup"
     },
     {
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
        "op": "regex",
        "value": "(?i)^(lookup.*|.*key)$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it"
  },
  {
   "id": "k_dedup",
   "kind": "exists",
   "tier": "core",
   "quote": "a deduplication table keyed on a dedup hash",
   "select": {
    "types": [
     "AWS::DynamoDB::Table",
     "AWS::DynamoDB::GlobalTable"
    ],
    "where": [
     {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)dedup|duplicat"
     },
     {
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
        "op": "regex",
        "value": "(?i)^(dedup(lication)?[-_]?)?hash$"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       }
      ]
     }
    ]
   },
   "justify": "keyed on means the partition (HASH) key; the table is recognised by the purpose word the prompt gives it"
  },
  {
   "id": "outputs",
   "kind": "exists",
   "tier": "detail",
   "quote": "have their names published as stack outputs",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "present"
     },
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "absent"
     },
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "^\\{\"ref\"|^socless_|^\\$\\{[^}]+\\}$"
     }
    ]
   },
   "distinct_path": [
    "value"
   ],
   "min": 6,
   "justify": "six tables stated, so six distinct name outputs; Ref to a DynamoDB table returns its name, while GetAtt returns an ARN or stream ARN"
  },
  {
   "id": "x_hash_keytype",
   "kind": "attr",
   "tier": "extra",
   "select": "tables",
   "quantifier": "all",
   "cond": {
    "path": [
     "KeySchema",
     "*",
     "KeyType"
    ],
    "op": "eq",
    "value": "HASH",
    "every": true
   }
  },
  {
   "id": "x_string_keys",
   "kind": "attr",
   "tier": "extra",
   "select": "tables",
   "quantifier": "all",
   "cond": {
    "path": [
     "AttributeDefinitions",
     "*",
     "AttributeType"
    ],
    "op": "eq",
    "value": "S",
    "every": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
