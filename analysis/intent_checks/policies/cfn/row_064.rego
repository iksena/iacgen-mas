# GENERATED from specs/cfn/row_064.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_064

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
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "graphql_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "a simple pet shop GraphQL API using AWS AppSync"
  },
  {
   "id": "api_name",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "PetShopAPI"
   },
   "tier": "core",
   "quote": "The API should be named PetShopAPI"
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
   "quote": "use API_KEY authentication"
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
   "tier": "core",
   "quote": "with an API key for anonymous access"
  },
  {
   "id": "lambda_exists",
   "kind": "exists",
   "select": "fn",
   "tier": "core",
   "quote": "Create a Lambda function that returns a static list of pets"
  },
  {
   "id": "lambda_pet_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "specific names (Buddy, Mittens, Charlie)",
   "checks": [
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "contains",
      "value": "Buddy"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "contains",
      "value": "Mittens"
     }
    },
    {
     "kind": "attr",
     "select": "fn",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "contains",
      "value": "Charlie"
     }
    }
   ]
  },
  {
   "id": "schema_pet_type",
   "kind": "all_of",
   "tier": "detail",
   "quote": "Define a GraphQL schema with a Pet type",
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
      "value": "(?s)type\\s+Pet\\s*\\{[^}]*\\bid\\s*:"
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
      "value": "(?s)type\\s+Pet\\s*\\{[^}]*\\bname\\s*:"
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
      "value": "(?s)type\\s+Pet\\s*\\{[^}]*\\btype\\s*:"
     }
    }
   ]
  },
  {
   "id": "schema_getpets_query",
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
    "value": "getPets\\s*:\\s*\\[\\s*Pet"
   },
   "tier": "core",
   "quote": "a getPets query that returns a list of pets"
  },
  {
   "id": "lambda_datasource",
   "kind": "ref",
   "from": "ds",
   "to": "fn",
   "tier": "core",
   "quote": "with the Lambda function serving as the data source for the resolver"
  },
  {
   "id": "resolver_getpets",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::AppSync::Resolver"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "FieldName"
    ],
    "op": "eq",
    "value": "getPets"
   },
   "tier": "core",
   "quote": "the data source for the resolver"
  },
  {
   "id": "resolver_uses_datasource",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the data source for the resolver",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": []
     },
     "to": "ds"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::AppSync::Resolver"
      ],
      "where": []
     },
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
   "id": "output_api_url",
   "kind": "attr",
   "select": "out",
   "cond": {
    "path": [
     "value",
     "attr"
    ],
    "op": "eq",
    "value": "GraphQLUrl"
   },
   "tier": "detail",
   "quote": "Output the API URL"
  },
  {
   "id": "output_api_key",
   "kind": "ref",
   "from": "out",
   "to": {
    "types": [
     "AWS::AppSync::ApiKey"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "and API key"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
