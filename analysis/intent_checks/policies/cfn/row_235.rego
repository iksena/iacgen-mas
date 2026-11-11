package intent.cfn.row_235

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pg": {
   "types": [
    "AWS::Redshift::ClusterParameterGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_param_groups",
   "kind": "exists",
   "tier": "core",
   "quote": "two Redshift cluster parameter groups",
   "select": "pg",
   "min": 2,
   "max": 2
  },
  {
   "id": "family",
   "kind": "attr",
   "tier": "core",
   "quote": "under the \"redshift-1.0\" parameter group family",
   "select": "pg",
   "quantifier": "all",
   "cond": {
    "path": [
     "ParameterGroupFamily"
    ],
    "op": "eq",
    "value": "redshift-1.0"
   }
  },
  {
   "id": "description",
   "kind": "attr",
   "tier": "detail",
   "quote": "a description of \"parameter group\"",
   "select": "pg",
   "quantifier": "all",
   "cond": {
    "path": [
     "Description"
    ],
    "op": "eq",
    "value": "parameter group"
   }
  },
  {
   "id": "require_ssl",
   "kind": "attr",
   "tier": "core",
   "quote": "setting the \"require_ssl\" parameter value to true",
   "select": "pg",
   "quantifier": "all",
   "cond": {
    "path": [
     "Parameters",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ParameterName"
      ],
      "op": "eq",
      "value": "require_ssl"
     },
     {
      "path": [
       "ParameterValue"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
