package intent.cfn.row_262

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "api_named_simpletodoapi",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "SimpleTodoAPI"
   },
   "tier": "core",
   "quote": "The API should be named SimpleTodoAPI"
  },
  {
   "id": "api_key_auth",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   },
   "tier": "core",
   "quote": "use API key authentication"
  },
  {
   "id": "api_key_created",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::AppSync::ApiKey"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "with the key created by the template"
  },
  {
   "id": "schema_todo_type",
   "kind": "all_of",
   "tier": "core",
   "quote": "Define a schema covering a to-do item",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::AppSync::GraphQLSchema"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::AppSync::GraphQLApi"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::GraphQLSchema"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)\\btype\\s+\\w*to_?do\\w*\\s*(@\\w+\\s*)*\\{"
     }
    }
   ],
   "justify": "\"a schema covering a to-do item\" = an object type for the to-do item"
  },
  {
   "id": "dynamodb_data_source",
   "kind": "ref",
   "from": {
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
   "to": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "backed by a DynamoDB table"
  },
  {
   "id": "single_dynamodb_data_source",
   "kind": "exists",
   "select": {
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
   "max": 1,
   "tier": "detail",
   "quote": "against a single DynamoDB data source",
   "justify": "\"a single\" data source = exactly one"
  },
  {
   "id": "six_resolvers",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": []
   },
   "min": 6,
   "tier": "core",
   "quote": "wire six resolvers"
  },
  {
   "id": "resolvers_javascript",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "Runtime",
     "Name"
    ],
    "op": "eq",
    "value": "APPSYNC_JS"
   },
   "tier": "core",
   "quote": "using JavaScript resolvers rather than VTL mapping templates",
   "justify": "AppSync JavaScript resolvers run on the APPSYNC_JS runtime"
  },
  {
   "id": "no_vtl_templates",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "RequestMappingTemplate"
    ],
    "op": "absent"
   },
   "tier": "detail",
   "quote": "rather than VTL mapping templates"
  },
  {
   "id": "three_mutation_resolvers",
   "kind": "exists",
   "tier": "detail",
   "min": 3,
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": [
     {
      "path": [
       "TypeName"
      ],
      "op": "eq",
      "value": "Mutation"
     }
    ]
   },
   "quote": "mutations to create, update and delete a to-do",
   "justify": "create, update and delete = 3 Mutation fields"
  },
  {
   "id": "three_query_resolvers",
   "kind": "exists",
   "tier": "detail",
   "min": 3,
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": [
     {
      "path": [
       "TypeName"
      ],
      "op": "eq",
      "value": "Query"
     }
    ]
   },
   "quote": "queries to fetch one by identifier, list them all, and query them by owner",
   "justify": "get, list and query-by-owner = 3 Query fields"
  },
  {
   "id": "mutation_field_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "mutations to create, update and delete a to-do",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Mutation"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)^(create|add|new|put)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Mutation"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)^(update|edit|modify)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Mutation"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)^(delete|remove)"
     }
    }
   ]
  },
  {
   "id": "query_field_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "fetch one by identifier, list them all, and query them by owner",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Query"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)^(get|fetch|find)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Query"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)^(list|all)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": [
       {
        "path": [
         "TypeName"
        ],
        "op": "eq",
        "value": "Query"
       }
      ]
     },
     "cond": {
      "path": [
       "FieldName"
      ],
      "op": "regex",
      "value": "(?i)owner"
     }
    }
   ]
  },
  {
   "id": "resolvers_use_data_source",
   "kind": "any_of",
   "tier": "detail",
   "quote": "wire six resolvers against a single DynamoDB data source",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": []
     },
     "to": {
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
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": []
     },
     "from_path": [
      "DataSourceName"
     ],
     "to": {
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
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "owner_query_uses_index",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "AWS::AppSync::Resolver",
     "AWS::AppSync::FunctionConfiguration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Code"
    ],
    "op": "regex",
    "value": "(?is)['\"]?operation['\"]?\\s*:\\s*['\"]Query['\"].{0,1000}?\\bindex(Name)?['\"]?\\s*[:,}]|\\bindex(Name)?['\"]?\\s*:.{0,1000}?['\"]Query['\"]"
   },
   "quote": "query them by owner through a secondary index on the table"
  },
  {
   "id": "table_keyed_on_id",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "KeySchema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "HASH"
     },
     {
      "path": [
       "AttributeName"
      ],
      "op": "regex",
      "value": "(?i)id$"
     }
    ]
   },
   "tier": "core",
   "quote": "The table should be keyed on an item identifier",
   "justify": "\"keyed on an item identifier\" = the partition (HASH) key is the id attribute"
  },
  {
   "id": "table_owner_gsi",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "GlobalSecondaryIndexes",
     "*",
     "KeySchema",
     "*",
     "AttributeName"
    ],
    "op": "regex",
    "value": "(?i)owner"
   },
   "tier": "core",
   "quote": "carry the secondary index the owner query needs"
  },
  {
   "id": "appsync_service_role",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "appsync.amazonaws.com"
     }
    ]
   },
   "tier": "core",
   "quote": "create the service role AppSync assumes to read and write that table"
  },
  {
   "id": "role_read_dynamodb",
   "kind": "any_of",
   "tier": "core",
   "quote": "to read and write that table",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument",
         "Statement",
         "*",
         "Principal",
         "Service",
         "*"
        ],
        "op": "eq",
        "value": "appsync.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:GetItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument",
         "Statement",
         "*",
         "Principal",
         "Service",
         "*"
        ],
        "op": "eq",
        "value": "appsync.amazonaws.com"
       }
      ]
     },
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
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:GetItem"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "role_write_dynamodb",
   "kind": "any_of",
   "tier": "core",
   "quote": "to read and write that table",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument",
         "Statement",
         "*",
         "Principal",
         "Service",
         "*"
        ],
        "op": "eq",
        "value": "appsync.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "dynamodb:PutItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "AssumeRolePolicyDocument",
         "Statement",
         "*",
         "Principal",
         "Service",
         "*"
        ],
        "op": "eq",
        "value": "appsync.amazonaws.com"
       }
      ]
     },
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
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "dynamodb:PutItem"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "data_source_uses_role",
   "kind": "ref",
   "from": {
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
   "to": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument",
       "Statement",
       "*",
       "Principal",
       "Service",
       "*"
      ],
      "op": "eq",
      "value": "appsync.amazonaws.com"
     }
    ]
   },
   "tier": "detail",
   "quote": "the service role AppSync assumes"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
