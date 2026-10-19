package intent.cfn.row_180

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
  "fnc": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": []
  },
  "resolver": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "api_name",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "TodoAPIwithJs"
   },
   "tier": "core",
   "quote": "a self-contained AWS AppSync GraphQL API named \"TodoAPIwithJs\""
  },
  {
   "id": "api_key_auth",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   },
   "tier": "core",
   "quote": "with API key authentication"
  },
  {
   "id": "api_key_resource",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::AppSync::ApiKey"
    ],
    "where": []
   },
   "to": "api",
   "tier": "detail",
   "quote": "with API key authentication"
  },
  {
   "id": "table_gsi_on_owner",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "GlobalSecondaryIndexes",
     "*",
     "KeySchema",
     "*",
     "AttributeName"
    ],
    "op": "eq",
    "value": "owner"
   },
   "tier": "core",
   "quote": "backed by a DynamoDB table with a global secondary index on the owner attribute"
  },
  {
   "id": "dynamodb_datasource",
   "kind": "ref",
   "from": "ds",
   "to": "table",
   "tier": "detail",
   "quote": "backed by a DynamoDB table"
  },
  {
   "id": "schema_crud_mutations",
   "kind": "all_of",
   "tier": "core",
   "quote": "full CRUD operations (create, update, delete, get, list)",
   "checks": [
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
      "value": "(?s)type\\s+Mutation\\s*\\{[^}]*\\b(create|add|put)\\w*\\s*\\("
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
      "value": "(?s)type\\s+Mutation\\s*\\{[^}]*\\b(update|edit)\\w*\\s*\\("
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
      "value": "(?s)type\\s+Mutation\\s*\\{[^}]*\\b(delete|remove)\\w*\\s*\\("
     }
    }
   ]
  },
  {
   "id": "schema_get_list_queries",
   "kind": "all_of",
   "tier": "core",
   "quote": "full CRUD operations (create, update, delete, get, list)",
   "checks": [
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
      "value": "(?s)type\\s+Query\\s*\\{[^}]*\\bget\\w*\\s*\\("
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
      "value": "(?s)type\\s+Query\\s*\\{[^}]*\\b(list|all)\\w*\\s*[(:]"
     }
    }
   ]
  },
  {
   "id": "schema_query_by_owner",
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
    "value": "(?s)type\\s+Query\\s*\\{[^}]*\\(\\s*[^)]*\\bowner\\s*:"
   },
   "tier": "core",
   "quote": "as well as a query by owner index"
  },
  {
   "id": "schema_subscriptions",
   "kind": "all_of",
   "tier": "core",
   "quote": "real-time subscriptions for create, update, and delete events",
   "checks": [
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
      "value": "@aws_subscribe\\(\\s*mutations\\s*:\\s*\\[[^\\]]*\"(create|add|put)\\w*\""
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
      "value": "@aws_subscribe\\(\\s*mutations\\s*:\\s*\\[[^\\]]*\"(update|edit)\\w*\""
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
      "value": "@aws_subscribe\\(\\s*mutations\\s*:\\s*\\[[^\\]]*\"(delete|remove)\\w*\""
     }
    }
   ]
  },
  {
   "id": "pipeline_resolvers",
   "kind": "attr",
   "select": "resolver",
   "quantifier": "all",
   "cond": {
    "path": [
     "Kind"
    ],
    "op": "eq",
    "value": "PIPELINE"
   },
   "tier": "core",
   "quote": "all implemented as pipeline resolvers"
  },
  {
   "id": "js_resolvers",
   "kind": "any_of",
   "tier": "core",
   "quote": "using JavaScript resolvers",
   "checks": [
    {
     "kind": "attr",
     "select": "resolver",
     "quantifier": "all",
     "cond": {
      "path": [
       "Runtime",
       "Name"
      ],
      "op": "eq",
      "value": "APPSYNC_JS"
     }
    },
    {
     "kind": "attr",
     "select": "resolver",
     "quantifier": "all",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "export\\s+function\\s+(request|response)"
     }
    }
   ]
  },
  {
   "id": "resolver_count",
   "kind": "exists",
   "select": "resolver",
   "min": 6,
   "tier": "detail",
   "quote": "support full CRUD operations (create, update, delete, get, list) as well as a query by owner index",
   "justify": "six operations stated: create, update, delete, get, list, query by owner index"
  },
  {
   "id": "js_functions_per_operation",
   "kind": "exists",
   "min": 6,
   "select": {
    "types": [
     "AWS::AppSync::FunctionConfiguration"
    ],
    "where": [
     {
      "path": [
       "Runtime",
       "Name"
      ],
      "op": "eq",
      "value": "APPSYNC_JS"
     }
    ]
   },
   "tier": "core",
   "quote": "individual JavaScript functions for each data operation",
   "justify": "one function per each of the six stated data operations"
  },
  {
   "id": "resolvers_use_functions",
   "kind": "ref",
   "from": "resolver",
   "to": "fnc",
   "tier": "detail",
   "quote": "pipeline resolvers with individual JavaScript functions"
  },
  {
   "id": "functions_use_table_datasource",
   "kind": "any_of",
   "tier": "detail",
   "quote": "backed by a DynamoDB table",
   "checks": [
    {
     "kind": "ref",
     "from": "fnc",
     "to": "ds"
    },
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "DataSourceName"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "function_data_operations",
   "kind": "all_of",
   "tier": "detail",
   "quote": "individual JavaScript functions for each data operation",
   "checks": [
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)PutItem|\\bput\\s*\\("
     }
    },
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)UpdateItem|\\bupdate\\s*\\("
     }
    },
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)DeleteItem|\\b(remove|delete)\\s*\\("
     }
    },
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)GetItem|\\bget\\s*\\("
     }
    },
    {
     "kind": "attr",
     "select": "fnc",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)query.*index|index.*query"
     }
    }
   ],
   "justify": "create/update/delete/get/query map to the DynamoDB put/update/delete/get/query operations; helper-module call names accepted"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
