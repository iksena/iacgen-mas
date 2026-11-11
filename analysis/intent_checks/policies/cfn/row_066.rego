package intent.cfn.row_066

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
  "schema": {
   "types": [
    "AWS::AppSync::GraphQLSchema"
   ],
   "where": []
  },
  "fn": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": []
  },
  "res": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": [
    {
     "path": [
      "Kind"
     ],
     "op": "eq",
     "value": "PIPELINE"
    }
   ]
  },
  "ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": []
  },
  "res_any": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_apis",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "creates two AppSync GraphQL APIs",
   "min": 2,
   "max": 2
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
   "quote": "both using API_KEY authentication",
   "quantifier": "all"
  },
  {
   "id": "two_schemas",
   "kind": "exists",
   "select": "schema",
   "tier": "core",
   "quote": "a simple inline schema with a Book type",
   "min": 2,
   "justify": "each of the two APIs gets its own schema"
  },
  {
   "id": "schema_book",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Book\\b"
   },
   "tier": "core",
   "quote": "a Book type",
   "quantifier": "all"
  },
  {
   "id": "schema_get_book",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\b[^}]*\\bgetBook\\b"
   },
   "tier": "core",
   "quote": "a getBook query",
   "quantifier": "all"
  },
  {
   "id": "schema_book_id",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Book\\b[^}]*\\bID\\b"
   },
   "tier": "detail",
   "quote": "returns a generated ID and the requested book name",
   "quantifier": "all",
   "justify": "a generated ID implies an ID-typed field on Book"
  },
  {
   "id": "schema_book_name",
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
      "value": "(?is)type\\s+Book\\b[^}]*name"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?is)getBook\\s*\\([^)]*name"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "returns a generated ID and the requested book name",
   "justify": "the requested book name means an argument on getBook and a name field on Book"
  },
  {
   "id": "js_function",
   "kind": "exists",
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
   "quote": "a single AppSync JS function"
  },
  {
   "id": "pipeline_resolver",
   "kind": "exists",
   "select": "res",
   "tier": "core",
   "quote": "with a single AppSync JS function pipeline resolver",
   "min": 2,
   "justify": "both APIs share the description, so each API gets the resolver"
  },
  {
   "id": "resolver_single_function",
   "kind": "attr",
   "select": "res",
   "cond": {
    "path": [
     "PipelineConfig",
     "Functions"
    ],
    "op": "len_eq",
    "value": 1
   },
   "quantifier": "all",
   "tier": "detail",
   "quote": "with a single AppSync JS function pipeline resolver"
  },
  {
   "id": "resolver_get_book",
   "kind": "attr",
   "select": "res_any",
   "cond": {
    "path": [
     "FieldName"
    ],
    "op": "eq",
    "value": "getBook"
   },
   "tier": "detail",
   "quote": "a getBook query",
   "quantifier": "all"
  },
  {
   "id": "resolver_uses_function",
   "kind": "ref",
   "from": "res",
   "to": "fn",
   "tier": "detail",
   "quote": "with a single AppSync JS function pipeline resolver"
  },
  {
   "id": "generated_id",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)auto(id|ulid|ksuid)|uuid"
     }
    },
    {
     "kind": "attr",
     "select": "res_any",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)auto(id|ulid|ksuid)|uuid"
     }
    }
   ],
   "tier": "detail",
   "quote": "returns a generated ID",
   "justify": "a generated ID in an AppSync JS function is util.autoId / uuid"
  },
  {
   "id": "returns_requested_name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "ctx\\.arg"
     }
    },
    {
     "kind": "attr",
     "select": "res_any",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "ctx\\.arg"
     }
    }
   ],
   "tier": "detail",
   "quote": "the requested book name",
   "justify": "the requested value is read from the query arguments (ctx.args / ctx.arguments)"
  },
  {
   "id": "second_api_introspection_off",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": [
     {
      "path": [
       "IntrospectionConfig"
      ],
      "op": "eq",
      "value": "DISABLED"
     }
    ]
   },
   "tier": "core",
   "quote": "the second API must have introspection disabled"
  },
  {
   "id": "second_api_limits",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": [
     {
      "path": [
       "IntrospectionConfig"
      ],
      "op": "eq",
      "value": "DISABLED"
     },
     {
      "path": [
       "QueryDepthLimit"
      ],
      "op": "eq",
      "value": 10
     },
     {
      "path": [
       "ResolverCountLimit"
      ],
      "op": "eq",
      "value": 100
     }
    ]
   },
   "tier": "core",
   "quote": "introspection disabled, a query depth limit of 10, and a resolver count limit of 100"
  },
  {
   "id": "depth_limit",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": [
     {
      "path": [
       "QueryDepthLimit"
      ],
      "op": "eq",
      "value": 10
     }
    ]
   },
   "tier": "detail",
   "quote": "a query depth limit of 10"
  },
  {
   "id": "resolver_limit",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::AppSync::GraphQLApi"
    ],
    "where": [
     {
      "path": [
       "ResolverCountLimit"
      ],
      "op": "eq",
      "value": 100
     }
    ]
   },
   "tier": "detail",
   "quote": "a resolver count limit of 100"
  },
  {
   "id": "first_api_default_introspection",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::AppSync::GraphQLApi"
      ],
      "where": [
       {
        "path": [
         "IntrospectionConfig"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::AppSync::GraphQLApi"
      ],
      "where": [
       {
        "path": [
         "IntrospectionConfig"
        ],
        "op": "eq",
        "value": "ENABLED"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "The first API should have default introspection settings"
  },
  {
   "id": "x_none_ds",
   "kind": "exists",
   "tier": "extra",
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
      "value": "NONE"
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_appsync_apikey",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::AppSync::ApiKey"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_iam_role",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
