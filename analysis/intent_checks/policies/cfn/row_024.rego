package intent.cfn.row_024

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
  "log_role": {
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
  },
  "log_policy": {
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
     "value": "logs:PutLogEvents"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "a private AWS AppSync GraphQL API"
  },
  {
   "id": "name",
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
   "quote": "named \"SuperCoolAPI\""
  },
  {
   "id": "private",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Visibility"
    ],
    "op": "eq",
    "value": "PRIVATE"
   },
   "tier": "core",
   "quote": "a private AWS AppSync GraphQL API"
  },
  {
   "id": "iam_auth",
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
   "quote": "secured with AWS IAM authentication"
  },
  {
   "id": "field_log_all",
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
   "quote": "logging enabled to CloudWatch at the field level for all operations",
   "justify": "field level for all operations maps to FieldLogLevel ALL"
  },
  {
   "id": "introspection_disabled",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "IntrospectionConfig"
    ],
    "op": "eq",
    "value": "DISABLED"
   },
   "tier": "core",
   "quote": "schema introspection disabled for security"
  },
  {
   "id": "depth_limit",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "QueryDepthLimit"
    ],
    "op": "eq",
    "value": 10
   },
   "tier": "core",
   "quote": "a query depth limit of 10"
  },
  {
   "id": "resolver_limit",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "ResolverCountLimit"
    ],
    "op": "eq",
    "value": 100
   },
   "tier": "core",
   "quote": "a resolver count limit of 100"
  },
  {
   "id": "schema",
   "kind": "exists",
   "select": "schema",
   "tier": "core",
   "quote": "a simple schema"
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
    "value": "(?s)type\\s+Book\\s*\\{[^}]*bookName"
   },
   "tier": "detail",
   "quote": "a Book type containing a bookName field"
  },
  {
   "id": "schema_query",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\s*\\{[^}]*getBook"
   },
   "tier": "detail",
   "quote": "a Query type with a getBook resolver"
  },
  {
   "id": "log_role",
   "kind": "exists",
   "select": "log_role",
   "tier": "core",
   "quote": "the necessary IAM role for AppSync to push logs to CloudWatch",
   "justify": "AppSync assumes the role through its service principal"
  },
  {
   "id": "api_uses_role",
   "kind": "ref",
   "from": "api",
   "to": "log_role",
   "tier": "detail",
   "quote": "the necessary IAM role for AppSync to push logs to CloudWatch",
   "justify": "AppSync assumes the role through its service principal"
  },
  {
   "id": "role_can_push_logs",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "log_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSAppSyncPushToCloudWatchLogs|CloudWatchLogsFullAccess"
     }
    },
    {
     "kind": "attr",
     "select": "log_role",
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
      "value": "logs:PutLogEvents"
     }
    },
    {
     "kind": "ref",
     "from": "log_policy",
     "to": "log_role",
     "bidirectional": true
    }
   ],
   "quote": "IAM role for AppSync to push logs to CloudWatch",
   "justify": "pushing logs needs logs:PutLogEvents, which the AWS managed AppSync logging policy grants"
  },
  {
   "id": "tag",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "graphqlapi:createdBy",
     "value": "SAM"
    }
   },
   "tier": "detail",
   "quote": "tag the API with the key \"graphqlapi:createdBy\" set to \"SAM\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
