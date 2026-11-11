package intent.cfn.row_101

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
  "key": {
   "types": [
    "AWS::AppSync::ApiKey"
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
     "value": "NONE"
    }
   ]
  },
  "res": {
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
    },
    {
     "path": [
      "FieldName"
     ],
     "op": "eq",
     "value": "publish2channel"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "graphql_api",
   "tier": "core",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "WS-API"
   },
   "quote": "an AWS AppSync GraphQL API named \"WS-API\""
  },
  {
   "id": "api_key_auth",
   "tier": "core",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "API_KEY"
   },
   "quote": "with API_KEY authentication"
  },
  {
   "id": "schema",
   "tier": "core",
   "kind": "exists",
   "select": "schema",
   "quote": "The API must include a schema"
  },
  {
   "id": "channel_type",
   "tier": "core",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "match",
    "value": [
     {
      "path": [],
      "op": "regex",
      "value": "(?s)type\\s+Channel\\s*\\{[^}]*name\\s*:\\s*String!"
     },
     {
      "path": [],
      "op": "regex",
      "value": "(?s)type\\s+Channel\\s*\\{[^}]*data\\s*:\\s*AWSJSON!"
     }
    ]
   },
   "quote": "a \"Channel\" type with \"name\" (String!) and \"data\" (AWSJSON!) fields"
  },
  {
   "id": "get_channel_query",
   "tier": "core",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\s*\\{[^}]*getChannel"
   },
   "quote": "a \"getChannel\" query"
  },
  {
   "id": "publish_mutation",
   "tier": "core",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Mutation\\s*\\{[^}]*publish2channel\\s*\\(\\s*(name\\s*:\\s*String!\\s*,?\\s*data\\s*:\\s*AWSJSON!|data\\s*:\\s*AWSJSON!\\s*,?\\s*name\\s*:\\s*String!)\\s*\\)\\s*:\\s*Channel"
   },
   "quote": "a \"publish2channel\" mutation that accepts \"name\" (String!) and \"data\" (AWSJSON!) and returns a Channel"
  },
  {
   "id": "subscribe_subscription",
   "tier": "core",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Subscription\\s*\\{[^}]*subscribe2channel\\s*\\(\\s*name\\s*:\\s*String!\\s*\\)"
   },
   "quote": "a \"subscribe2channel\" subscription that accepts a \"name\" (String!)"
  },
  {
   "id": "subscribe_annotation",
   "tier": "core",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)subscribe2channel[^}]*@aws_subscribe\\s*\\(\\s*mutations\\s*:\\s*\\[[^\\]]*\"publish2channel\""
   },
   "quote": "is annotated to trigger on the \"publish2channel\" mutation"
  },
  {
   "id": "schema_on_api",
   "tier": "detail",
   "kind": "ref",
   "from": "schema",
   "to": "api",
   "quote": "The API must include a schema"
  },
  {
   "id": "none_datasource",
   "tier": "core",
   "kind": "attr",
   "select": "ds",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "pubsub"
   },
   "quote": "a NONE-type data source named \"pubsub\""
  },
  {
   "id": "publish_resolver",
   "tier": "core",
   "kind": "exists",
   "select": "res",
   "quote": "the resolver for the publish2channel mutation"
  },
  {
   "id": "resolver_unit",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "res",
     "cond": {
      "path": [
       "Kind"
      ],
      "op": "eq",
      "value": "UNIT"
     }
    },
    {
     "kind": "attr",
     "select": "res",
     "cond": {
      "path": [
       "Kind"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "must be a UNIT resolver",
   "justify": "UNIT is also the default Kind when omitted"
  },
  {
   "id": "resolver_datasource",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "res",
     "cond": {
      "path": [
       "DataSourceName"
      ],
      "op": "eq",
      "value": "pubsub"
     }
    },
    {
     "kind": "ref",
     "from": "res",
     "to": "ds"
    }
   ],
   "quote": "The API should use a NONE-type data source named \"pubsub\" for the resolver"
  },
  {
   "id": "resolver_payload",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "res",
     "cond": {
      "path": [
       "RequestMappingTemplate"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)payload"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)(context\\.arguments|ctx\\.arg|context\\.args)"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "res",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)payload"
       },
       {
        "path": [],
        "op": "regex",
        "value": "(?i)(arguments|ctx\\.arg|context\\.args)"
       }
      ]
     }
    }
   ],
   "quote": "that passes the arguments directly as the payload",
   "justify": "passes arguments as payload"
  },
  {
   "id": "default_api_key",
   "tier": "core",
   "kind": "exists",
   "select": "key",
   "quote": "a default API key"
  },
  {
   "id": "key_on_api",
   "tier": "detail",
   "kind": "ref",
   "from": "key",
   "to": "api",
   "quote": "a default API key"
  },
  {
   "id": "out_graphql_url",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "GraphQLUrl"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)appsync-api"
       }
      ]
     }
    }
   ],
   "quote": "expose the GraphQL URL"
  },
  {
   "id": "out_api_key",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(\"attr\": \"ApiKey\"|\\.ApiKey\\})"
     }
    ]
   },
   "quote": "API key"
  },
  {
   "id": "out_api_id",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(\"attr\": \"ApiId\"|\\.ApiId\\})"
     }
    ]
   },
   "quote": "API ID"
  },
  {
   "id": "out_region",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "^[a-z]{2}(-[a-z]+)+-[0-9]$"
     }
    ]
   },
   "quote": "and region as outputs",
   "justify": "a region name value"
  },
  {
   "id": "x_response_mapping",
   "tier": "extra",
   "kind": "attr",
   "select": "res",
   "cond": {
    "path": [
     "ResponseMappingTemplate"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
