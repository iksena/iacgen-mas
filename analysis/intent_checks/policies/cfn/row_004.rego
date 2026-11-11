package intent.cfn.row_004

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cluster": {
   "types": [
    "AWS::Route53RecoveryControl::Cluster"
   ],
   "where": []
  },
  "panels": {
   "types": [
    "AWS::Route53RecoveryControl::ControlPanel"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "cluster",
   "kind": "exists",
   "select": "cluster",
   "tier": "core",
   "quote": "a single cluster",
   "max": 1,
   "justify": "'a single' cluster = at most one"
  },
  {
   "id": "panel_external",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Route53RecoveryControl::ControlPanel"
    ],
    "where": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "ExternalApiControlPanel"
     }
    ]
   },
   "tier": "core",
   "quote": "ExternalApiControlPanel"
  },
  {
   "id": "panel_service1",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Route53RecoveryControl::ControlPanel"
    ],
    "where": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "Service1ControlPanel"
     }
    ]
   },
   "tier": "core",
   "quote": "Service1ControlPanel"
  },
  {
   "id": "panel_service2",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Route53RecoveryControl::ControlPanel"
    ],
    "where": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "Service2ControlPanel"
     }
    ]
   },
   "tier": "core",
   "quote": "Service2ControlPanel"
  },
  {
   "id": "three_panels",
   "kind": "exists",
   "select": "panels",
   "tier": "detail",
   "quote": "three separate control panels",
   "min": 3,
   "max": 3
  },
  {
   "id": "panels_in_cluster",
   "kind": "all_of",
   "tier": "core",
   "quote": "all associated with that cluster",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53RecoveryControl::ControlPanel"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "ExternalApiControlPanel"
       }
      ]
     },
     "to": "cluster"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53RecoveryControl::ControlPanel"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "Service1ControlPanel"
       }
      ]
     },
     "to": "cluster"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53RecoveryControl::ControlPanel"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "Service2ControlPanel"
       }
      ]
     },
     "to": "cluster"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
