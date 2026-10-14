# GENERATED from specs/cfn/row_137.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_137

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
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "http_ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": [
    {
     "path": [
      "Type"
     ],
     "op": "eq",
     "value": "HTTP"
    }
   ]
  },
  "ddb_ds": {
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
  "fn": {
   "types": [
    "AWS::AppSync::FunctionConfiguration"
   ],
   "where": []
  },
  "ticker_resolver": {
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
    },
    {
     "path": [
      "FieldName"
     ],
     "op": "eq",
     "value": "ticker"
    }
   ]
  },
  "history_resolver": {
   "types": [
    "AWS::AppSync::Resolver"
   ],
   "where": [
    {
     "path": [
      "TypeName"
     ],
     "op": "eq",
     "value": "TickerInfo"
    },
    {
     "path": [
      "FieldName"
     ],
     "op": "eq",
     "value": "priceHistory"
    }
   ]
  },
  "appsync_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "appsync.amazonaws.com"
    }
   ]
  },
  "apikey": {
   "types": [
    "AWS::AppSync::ApiKey"
   ],
   "where": []
  },
  "decl_schema": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::AppSync::GraphQLSchema"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "api_exists_named",
   "kind": "attr",
   "select": "api",
   "tier": "core",
   "quote": "named CryptoTickerAPI",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "CryptoTickerAPI"
   }
  },
  {
   "id": "api_key_auth",
   "kind": "attr",
   "select": "api",
   "tier": "core",
   "quote": "using AWS AppSync with API key authentication",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   }
  },
  {
   "id": "default_api_key",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::AppSync::ApiKey"
    ],
    "where": []
   },
   "to": "api",
   "tier": "detail",
   "quote": "should create a default API key after the schema is defined"
  },
  {
   "id": "api_key_after_schema",
   "kind": "any_of",
   "tier": "detail",
   "quote": "should create a default API key after the schema is defined",
   "checks": [
    {
     "kind": "join",
     "from": "apikey",
     "from_path": [
      "__resource__",
      "DependsOn",
      "*"
     ],
     "to": "decl_schema",
     "to_path": [
      "name"
     ]
    },
    {
     "kind": "ref",
     "from": "apikey",
     "to": "schema"
    }
   ]
  },
  {
   "id": "table_named",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "a DynamoDB table named APIDataTable",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "eq",
    "value": "APIDataTable"
   }
  },
  {
   "id": "composite_key",
   "kind": "all_of",
   "tier": "core",
   "quote": "a composite primary key (hash key hk and range key sk, both strings)",
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
        "value": "hk"
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
        "value": "sk"
       },
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "RANGE"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "key_attrs_strings",
   "kind": "all_of",
   "tier": "detail",
   "quote": "both strings",
   "checks": [
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
        "value": "hk"
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
        "value": "sk"
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
   ]
  },
  {
   "id": "on_demand_billing",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "using on-demand billing",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "justify": "on-demand billing is BillingMode PAY_PER_REQUEST"
  },
  {
   "id": "table_deletion_retain",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "with a deletion policy of Retain to preserve data",
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Retain"
   }
  },
  {
   "id": "sse_disabled",
   "kind": "any_of",
   "tier": "detail",
   "quote": "server-side encryption disabled",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "SSESpecification",
       "SSEEnabled"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "SSESpecification"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "http_datasource_coingecko",
   "kind": "attr",
   "select": "http_ds",
   "tier": "core",
   "quote": "fetches the current price from the CoinGecko API via an HTTP data source",
   "cond": {
    "path": [
     "HttpConfig",
     "Endpoint"
    ],
    "op": "contains",
    "value": "coingecko"
   }
  },
  {
   "id": "ddb_datasource_table",
   "kind": "ref",
   "from": "ddb_ds",
   "to": "table",
   "tier": "core",
   "quote": "backed by a DynamoDB table named APIDataTable"
  },
  {
   "id": "ticker_pipeline_resolver",
   "kind": "attr",
   "select": "ticker_resolver",
   "tier": "core",
   "quote": "using a pipeline resolver composed of two AppSync functions",
   "cond": {
    "path": [
     "Kind"
    ],
    "op": "eq",
    "value": "PIPELINE"
   }
  },
  {
   "id": "pipeline_two_functions",
   "kind": "all_of",
   "tier": "core",
   "quote": "a pipeline resolver composed of two AppSync functions",
   "checks": [
    {
     "kind": "attr",
     "select": "ticker_resolver",
     "cond": {
      "path": [
       "PipelineConfig",
       "Functions"
      ],
      "op": "len_eq",
      "value": 2
     }
    },
    {
     "kind": "ref",
     "from": "ticker_resolver",
     "to": "fn"
    }
   ],
   "justify": "prompt states \"two AppSync functions\""
  },
  {
   "id": "fetch_function_http",
   "kind": "any_of",
   "tier": "detail",
   "quote": "fetches the current price from the CoinGecko API via an HTTP data source",
   "checks": [
    {
     "kind": "ref",
     "from": "fn",
     "to": "http_ds"
    },
    {
     "kind": "join",
     "from": "fn",
     "from_path": [
      "DataSourceName"
     ],
     "to": "http_ds",
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "store_function_putitem",
   "kind": "any_of",
   "tier": "detail",
   "quote": "stores a historical price record (including ticker, price in USD, and timestamp) into the DynamoDB table",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?is)PutItem.*timestamp|timestamp.*PutItem"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)PutItem.*timestamp|timestamp.*PutItem"
     }
    }
   ]
  },
  {
   "id": "schema_query_ticker",
   "kind": "attr",
   "select": "schema",
   "tier": "detail",
   "quote": "expose a Query.ticker field that, when invoked with a ticker symbol",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\s*\\{[^}]*\\bticker\\s*\\("
   }
  },
  {
   "id": "schema_price_history_next_token",
   "kind": "attr",
   "select": "schema",
   "tier": "detail",
   "quote": "a priceHistory field on the TickerInfo type",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+TickerInfo\\s*\\{[^}]*\\bpriceHistory\\s*\\([^)]*nextToken"
   }
  },
  {
   "id": "history_resolver_queries_table",
   "kind": "any_of",
   "tier": "core",
   "quote": "queries the DynamoDB table for all records matching that ticker",
   "checks": [
    {
     "kind": "ref",
     "from": "history_resolver",
     "to": "ddb_ds"
    },
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "contains",
      "value": "\"Query\""
     }
    },
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "contains",
      "value": "Query"
     }
    }
   ]
  },
  {
   "id": "history_descending",
   "kind": "any_of",
   "tier": "detail",
   "quote": "sorted in descending order by the range key",
   "checks": [
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?i)scanIndexForward\"?\\s*:\\s*false"
     }
    },
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?i)scanIndexForward\"?\\s*:\\s*false"
     }
    }
   ],
   "justify": "descending sort by range key in a DynamoDB Query resolver is scanIndexForward false"
  },
  {
   "id": "history_default_limit_25",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with a default limit of 25 items",
   "checks": [
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "regex",
      "value": "(?s)limit.{0,80}\\b25\\b"
     }
    },
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?s)limit.{0,80}\\b25\\b"
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
      "value": "(?s)priceHistory\\s*\\([^)]*limit\\s*:\\s*Int!?\\s*=\\s*25\\b"
     }
    }
   ]
  },
  {
   "id": "history_pagination",
   "kind": "any_of",
   "tier": "detail",
   "quote": "support for pagination via a nextToken argument",
   "checks": [
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "contains",
      "value": "nextToken"
     }
    },
    {
     "kind": "attr",
     "select": "history_resolver",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "contains",
      "value": "nextToken"
     }
    }
   ]
  },
  {
   "id": "ddb_ds_role",
   "kind": "ref",
   "from": "ddb_ds",
   "to": "appsync_role",
   "tier": "detail",
   "quote": "IAM roles and policies for AppSync to assume and interact with both the DynamoDB table"
  },
  {
   "id": "http_ds_role",
   "kind": "ref",
   "from": "http_ds",
   "to": "appsync_role",
   "tier": "detail",
   "quote": "and the external HTTP endpoint"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
