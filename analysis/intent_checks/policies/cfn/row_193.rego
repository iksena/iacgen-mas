package intent.cfn.row_193

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::AppSync::GraphQLApi"
   ],
   "where": []
  },
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": [
    {
     "path": [
      "Type"
     ],
     "op": "eq",
     "value": "AMAZON_DYNAMODB"
    }
   ]
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "schema": {
   "types": [
    "AWS::AppSync::GraphQLSchema"
   ],
   "where": []
  },
  "role_appsync": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "appsync\\.amazonaws\\.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "graphql_api",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "SuperCoolAPI"
   },
   "tier": "core",
   "quote": "an AppSync GraphQL API named \"SuperCoolAPI\""
  },
  {
   "id": "api_iam_auth",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "AWS_IAM"
   },
   "tier": "core",
   "quote": "AWS IAM authentication"
  },
  {
   "id": "api_field_log_level_all",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "LogConfig",
     "FieldLogLevel"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "tier": "core",
   "quote": "full CloudWatch Logs request logging",
   "justify": "full logging means field log level ALL"
  },
  {
   "id": "api_logs_role",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "LogConfig",
     "CloudWatchLogsRoleArn"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "full CloudWatch Logs request logging"
  },
  {
   "id": "table_name",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "eq",
    "value": "Table1"
   },
   "tier": "core",
   "quote": "a DynamoDB table named \"Table1\""
  },
  {
   "id": "table_id_string_key",
   "kind": "all_of",
   "checks": [
    {
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
     }
    },
    {
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
     }
    }
   ],
   "tier": "core",
   "quote": "an \"id\" string primary key",
   "justify": "a primary key with no sort key is the HASH key"
  },
  {
   "id": "table_on_demand",
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
   "quote": "on-demand billing",
   "justify": "on-demand billing is PAY_PER_REQUEST"
  },
  {
   "id": "data_sources",
   "kind": "exists",
   "select": "ds",
   "min": 2,
   "tier": "core",
   "quote": "multiple DynamoDB data sources",
   "justify": "multiple means at least two"
  },
  {
   "id": "data_sources_to_table",
   "kind": "attr",
   "select": "ds",
   "quantifier": "all",
   "cond": {
    "path": [
     "DynamoDBConfig",
     "TableName"
    ],
    "op": "regex",
    "value": "(?i)^table1$|ref|\\$\\{"
   },
   "tier": "core",
   "quote": "connected to the table",
   "justify": "every DynamoDB data source names the stated table Table1, literally or through a reference to it"
  },
  {
   "id": "data_sources_in_api",
   "kind": "ref",
   "to": "api",
   "tier": "detail",
   "quote": "multiple DynamoDB data sources",
   "from": {
    "types": [
     "AWS::AppSync::DataSource"
    ],
    "where": []
   }
  },
  {
   "id": "data_sources_different_referencing",
   "tier": "detail",
   "quote": "using different approaches to table and region referencing",
   "justify": "different approaches means the data sources do not all use one form",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "ds",
     "distinct_path": [
      "DynamoDBConfig",
      "TableName"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": "ds",
     "distinct_path": [
      "DynamoDBConfig",
      "AwsRegion"
     ],
     "min": 2
    }
   ]
  },
  {
   "id": "iam_roles",
   "tier": "core",
   "quote": "IAM roles and policies",
   "kind": "exists",
   "select": "role",
   "min": 2,
   "justify": "'IAM roles' is plural"
  },
  {
   "id": "data_source_uses_role",
   "tier": "detail",
   "quote": "IAM roles and policies granting full read-write access to the DynamoDB table",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ds",
     "to": "role_appsync"
    },
    {
     "kind": "attr",
     "select": "ds",
     "quantifier": "all",
     "cond": {
      "path": [
       "ServiceRoleArn"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "dynamodb_read",
   "tier": "core",
   "quote": "granting full read-write access to the DynamoDB table",
   "kind": "any_of",
   "justify": "read access means GetItem, Query and Scan, on a role AppSync assumes",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "(?i)(^|[^:])dynamodb:(\\*|Get\\*|GetItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])dynamodb:(\\*|Query\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])dynamodb:(\\*|Scan\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     },
     "to": "role_appsync"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument"
        ],
        "op": "regex",
        "value": "appsync\\.amazonaws\\.com"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Get\\*|GetItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Query\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Scan\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "dynamodb_write",
   "tier": "core",
   "quote": "granting full read-write access to the DynamoDB table",
   "kind": "any_of",
   "justify": "write access means PutItem, UpdateItem and DeleteItem, on a role AppSync assumes",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
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
        "value": "(?i)(^|[^:])dynamodb:(\\*|Put\\*|PutItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])dynamodb:(\\*|Update\\*|UpdateItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "regex",
        "value": "(?i)(^|[^:])dynamodb:(\\*|Delete\\*|DeleteItem\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     },
     "to": "role_appsync"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument"
        ],
        "op": "regex",
        "value": "appsync\\.amazonaws\\.com"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Put\\*|PutItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Update\\*|UpdateItem\\*?)([^A-Za-z0-9_]|$)"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)AmazonDynamoDBFullAccess|(^|[^:])dynamodb:(\\*|Delete\\*|DeleteItem\\*?)([^A-Za-z0-9_]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_covers_indexes",
   "tier": "core",
   "quote": "and its secondary indexes",
   "kind": "any_of",
   "justify": "all secondary indexes means a DynamoDB statement on an index/* or broader resource",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "regex",
          "value": "(?i)^(dynamodb:|\\*$)"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "index/\\*|table/\\*|^\\*$"
         }
        ]
       }
      ]
     },
     "to": "role_appsync"
    },
    {
     "kind": "attr",
     "select": "role_appsync",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(dynamodb:|\\*$)"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "index/\\*|table/\\*|^\\*$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "role_appsync",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDBFullAccess"
     }
    }
   ]
  },
  {
   "id": "schema_todo_type",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Todo\\b[^}]*\\bid\\s*:"
     }
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Todo\\b[^}]*\\bdescription\\s*:"
     }
    }
   ],
   "tier": "core",
   "quote": "a Todo type with id and description fields"
  },
  {
   "id": "schema_get_todo",
   "tier": "core",
   "quote": "a getTodo query",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+\\w*Query\\w*\\b[^}]*\\bgetTodo\\b"
   }
  },
  {
   "id": "schema_add_todo",
   "tier": "core",
   "quote": "an addTodo mutation",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+\\w*Mutation\\w*\\b[^}]*\\baddTodo\\b"
   }
  },
  {
   "id": "schema_in_api",
   "kind": "ref",
   "to": "api",
   "tier": "detail",
   "quote": "a GraphQL schema",
   "from": "schema"
  },
  {
   "id": "x_logs_role_managed_policy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSAppSyncPushToCloudWatchLogs"
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "logs:PutLogEvents"
     }
    }
   ],
   "tier": "extra"
  },
  {
   "id": "x_role_trusts_appsync",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "appsync\\.amazonaws\\.com"
   },
   "tier": "extra"
  },
  {
   "id": "x_logs_role_referenced",
   "kind": "ref",
   "to": "role",
   "tier": "extra",
   "from": "api"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
