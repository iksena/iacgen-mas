package intent.cfn.row_223

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rp": {
   "types": [
    "AWS::Redshift::ClusterParameterGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "four_groups",
   "kind": "exists",
   "select": "rp",
   "tier": "core",
   "quote": "four Redshift cluster parameter groups",
   "min": 4
  },
  {
   "id": "family",
   "kind": "attr",
   "select": "rp",
   "cond": {
    "path": [
     "ParameterGroupFamily"
    ],
    "op": "eq",
    "value": "redshift-1.0"
   },
   "tier": "core",
   "quote": "under the \"redshift-1.0\" parameter group family",
   "quantifier": "all"
  },
  {
   "id": "logging_groups",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Redshift::ClusterParameterGroup"
    ],
    "where": [
     {
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
        "value": "enable_user_activity_logging"
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
    ]
   },
   "tier": "core",
   "quote": "two parameter groups configured with user activity logging enabled (\"enable_user_activity_logging\" set to true)",
   "min": 2
  },
  {
   "id": "ssl_groups",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Redshift::ClusterParameterGroup"
    ],
    "where": [
     {
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
        "value": false
       }
      ]
     }
    ]
   },
   "tier": "core",
   "quote": "two parameter groups configured with SSL requirement explicitly disabled (\"require_ssl\" set to false)",
   "min": 2
  },
  {
   "id": "description",
   "kind": "attr",
   "select": "rp",
   "cond": {
    "path": [
     "Description"
    ],
    "op": "eq",
    "value": "parameter group"
   },
   "tier": "detail",
   "quote": "using description \"parameter group\" for each",
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
