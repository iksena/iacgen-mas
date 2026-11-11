package intent.cfn.row_022

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pg": {
   "types": [
    "AWS::DocDB::DBClusterParameterGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "param_group",
   "kind": "exists",
   "select": "pg",
   "tier": "core",
   "quote": "creates a DocumentDB cluster parameter group"
  },
  {
   "id": "pg_name",
   "kind": "attr",
   "select": "pg",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "test"
   },
   "tier": "core",
   "quote": "with the name \"test\""
  },
  {
   "id": "pg_family",
   "kind": "attr",
   "select": "pg",
   "cond": {
    "path": [
     "Family"
    ],
    "op": "eq",
    "value": "docdb3.6"
   },
   "tier": "core",
   "quote": "using family \"docdb3.6\""
  },
  {
   "id": "tls_disabled",
   "kind": "attr",
   "select": "pg",
   "cond": {
    "path": [
     "Parameters",
     "tls"
    ],
    "op": "eq",
    "value": "disabled"
   },
   "tier": "core",
   "quote": "with TLS disabled"
  },
  {
   "id": "ttl_monitor_enabled",
   "kind": "attr",
   "select": "pg",
   "cond": {
    "path": [
     "Parameters",
     "ttl_monitor"
    ],
    "op": "eq",
    "value": "enabled"
   },
   "tier": "core",
   "quote": "TTL monitoring enabled"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
