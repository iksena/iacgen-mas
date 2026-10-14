# GENERATED from specs/cfn/row_044.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_044

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "state_machine_standard",
   "kind": "any_of",
   "tier": "core",
   "quote": "a Step Functions standard workflow",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "StateMachineType"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "StateMachineType"
      ],
      "op": "eq",
      "value": "STANDARD"
     }
    }
   ]
  },
  {
   "id": "put_item_task",
   "kind": "any_of",
   "tier": "core",
   "quote": "call the PutItem API on a DynamoDB table",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:putItem"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:putItem"
     }
    }
   ]
  },
  {
   "id": "get_item_task",
   "kind": "any_of",
   "tier": "core",
   "quote": "call the GetItem API on the same table",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:getItem"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:getItem"
     }
    }
   ]
  },
  {
   "id": "id_from_input",
   "kind": "any_of",
   "tier": "detail",
   "quote": "using an ID from the execution input",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "contains",
      "value": "$.id"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "contains",
      "value": "$.id"
     }
    }
   ]
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?is)description.{0,200}?(States\\.Format|\\{%[^%]*&)"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?is)description.{0,200}?(States\\.Format|\\{%[^%]*&)"
     }
    }
   ],
   "id": "format_description",
   "tier": "detail",
   "quote": "formatting a description string"
  },
  {
   "id": "output_only_item",
   "kind": "any_of",
   "tier": "detail",
   "quote": "returning only the retrieved item as the final output",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "\\$\\.([A-Za-z0-9_]+\\.)*Item\\b"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "\\$\\.([A-Za-z0-9_]+\\.)*Item\\b"
     }
    }
   ]
  },
  {
   "id": "table_uses_same_table",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on the same table",
   "checks": [
    {
     "kind": "ref",
     "from": "sm",
     "to": "table"
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionSubstitutions"
      ],
      "op": "contains",
      "value": "my-table"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "contains",
      "value": "my-table"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "contains",
      "value": "my-table"
     }
    }
   ]
  },
  {
   "id": "table_id_attribute_string",
   "kind": "attr",
   "select": "table",
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
   "quote": "a string attribute named \"id\""
  },
  {
   "id": "table_id_partition_key",
   "kind": "attr",
   "select": "table",
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
   "quote": "as the partition key",
   "justify": "partition key = KeyType HASH"
  },
  {
   "id": "table_pay_per_request",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "tier": "core",
   "quote": "use the pay-per-request billing mode"
  },
  {
   "id": "table_name_default",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "contains",
    "value": "my-table"
   },
   "tier": "detail",
   "quote": "defaults to \"my-table\""
  },
  {
   "id": "table_name_parameter",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "my-table"
   },
   "tier": "detail",
   "quote": "its name should be configurable via a parameter"
  },
  {
   "id": "execution_role_in_stack",
   "kind": "ref",
   "from": "sm",
   "to": "role",
   "tier": "core",
   "quote": "The state machine's execution role must be created as part of the stack"
  },
  {
   "id": "role_trusts_states",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "states"
   },
   "tier": "detail",
   "quote": "The state machine's execution role"
  },
  {
   "id": "role_put_item_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "sufficient permissions to perform those DynamoDB actions on the table",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:(putitem|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)dynamodb:(putitem|\\*)"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AmazonDynamoDBFullAccess"
     }
    }
   ]
  },
  {
   "id": "role_get_item_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "sufficient permissions to perform those DynamoDB actions on the table",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)dynamodb:(getitem|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)dynamodb:(getitem|\\*)"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AmazonDynamoDB(FullAccess|ReadOnlyAccess)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
