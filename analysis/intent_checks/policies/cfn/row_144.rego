package intent.cfn.row_144

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "qd": {
   "types": [
    "AWS::Logs::QueryDefinition"
   ],
   "where": []
  },
  "dash": {
   "types": [
    "AWS::CloudWatch::Dashboard"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "query_definitions",
   "kind": "exists",
   "select": "qd",
   "min": 3,
   "tier": "core",
   "quote": "creates a set of CloudWatch Logs Insights queries",
   "justify": "queries cover three authentication methods"
  },
  {
   "id": "queries_cover_auth_methods",
   "tier": "core",
   "quote": "covering AD/SAML, Mutual Auth, and Mixed Auth authentication methods",
   "justify": "a query grouping by authentication type or method covers all the named methods",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "qd",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)saml|auth[a-z]*[-_ ]?(type|method)"
     }
    },
    {
     "kind": "attr",
     "select": "qd",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)mutual|auth[a-z]*[-_ ]?(type|method)"
     }
    },
    {
     "kind": "attr",
     "select": "qd",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)mix|auth[a-z]*[-_ ]?(type|method)"
     }
    }
   ]
  },
  {
   "id": "folder_param",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "aws-client-vpn"
     }
    ]
   },
   "tier": "core",
   "quote": "a parameter for an optional folder path to organize the queries (default 'aws-client-vpn')"
  },
  {
   "id": "queries_in_folder",
   "kind": "attr",
   "select": "qd",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "^aws-client-vpn/"
   },
   "quantifier": "all",
   "tier": "detail",
   "quote": "a parameter for an optional folder path to organize the queries"
  },
  {
   "id": "log_group_param",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "aws/aws-client-vpn/prod"
     }
    ]
   },
   "tier": "core",
   "quote": "a parameter for the Client VPN log group name (default 'aws/aws-client-vpn/prod')"
  },
  {
   "id": "log_group_used",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "qd",
     "cond": {
      "path": [
       "LogGroupNames",
       "*"
      ],
      "op": "eq",
      "value": "aws/aws-client-vpn/prod"
     }
    },
    {
     "kind": "attr",
     "select": "dash",
     "cond": {
      "path": [
       "DashboardBody"
      ],
      "op": "contains",
      "value": "aws/aws-client-vpn/prod"
     }
    }
   ],
   "tier": "detail",
   "quote": "the Client VPN log group name"
  },
  {
   "id": "dashboard",
   "kind": "exists",
   "select": "dash",
   "tier": "core",
   "quote": "a corresponding dashboard"
  },
  {
   "id": "dashboard_tables",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?is)view\"?\\s*:\\s*\"?table"
   },
   "tier": "core",
   "quote": "the dashboard should display tables"
  },
  {
   "id": "dashboard_four_tables",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?is)(view\"?\\s*:\\s*\"?table.*){4}"
   },
   "tier": "detail",
   "quote": "tables for total usage per endpoint, per authentication type, distinct users, and connection durations",
   "justify": "four tables are listed"
  },
  {
   "id": "dashboard_endpoint",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?i)(per|by)[ `'_-]*(client[ -]?vpn[ -]?|vpn[ -]?)?endpoint"
   },
   "tier": "detail",
   "quote": "total usage per endpoint"
  },
  {
   "id": "dashboard_auth_type",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?i)saml|mutual|mix|auth[a-z]*[-_ ]?(type|method)"
   },
   "tier": "detail",
   "quote": "per authentication type"
  },
  {
   "id": "dashboard_distinct_users",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?i)distinct|unique"
   },
   "tier": "detail",
   "quote": "distinct users"
  },
  {
   "id": "dashboard_durations",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?i)title[^,]{0,60}duration|(sum|avg|max|min)\\([^)]{0,40}duration"
   },
   "tier": "detail",
   "quote": "connection durations"
  },
  {
   "id": "x_query_endpoint_field",
   "kind": "attr",
   "select": "qd",
   "cond": {
    "path": [
     "QueryString"
    ],
    "op": "contains",
    "value": "client-vpn-endpoint-id"
   },
   "tier": "extra"
  },
  {
   "id": "x_query_duration_field",
   "kind": "attr",
   "select": "qd",
   "cond": {
    "path": [
     "QueryString"
    ],
    "op": "contains",
    "value": "connection-duration-seconds"
   },
   "tier": "extra"
  },
  {
   "id": "x_dashboard_log_widgets",
   "kind": "attr",
   "select": "dash",
   "cond": {
    "path": [
     "DashboardBody"
    ],
    "op": "regex",
    "value": "(?i)type\"?\\s*:\\s*\"?log"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
