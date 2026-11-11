package intent.cfn.row_242

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cl": {
   "types": [
    "AWS::Route53RecoveryControl::Cluster"
   ],
   "where": []
  },
  "cp": {
   "types": [
    "AWS::Route53RecoveryControl::ControlPanel"
   ],
   "where": []
  },
  "rc": {
   "types": [
    "AWS::Route53RecoveryControl::RoutingControl"
   ],
   "where": []
  },
  "sr": {
   "types": [
    "AWS::Route53RecoveryControl::SafetyRule"
   ],
   "where": []
  },
  "hc": {
   "types": [
    "AWS::Route53::HealthCheck"
   ],
   "where": []
  },
  "p_Region1": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Region1"
    }
   ]
  },
  "p_Region2": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Region2"
    }
   ]
  },
  "p_ProjectId": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "ProjectId"
    }
   ]
  },
  "hcs": {
   "types": [
    "AWS::Route53::HealthCheck"
   ],
   "where": [
    {
     "path": [
      "HealthCheckConfig",
      "Type"
     ],
     "op": "eq",
     "value": "RECOVERY_CONTROL"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "p_r1",
   "kind": "attr",
   "tier": "core",
   "select": "p_Region1",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "us-east-1"
   },
   "quote": "Region1 defaulting to \"us-east-1\""
  },
  {
   "id": "p_r2",
   "kind": "attr",
   "tier": "core",
   "select": "p_Region2",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "us-west-2"
   },
   "quote": "Region2 defaulting to \"us-west-2\""
  },
  {
   "id": "p_pid",
   "kind": "attr",
   "tier": "core",
   "select": "p_ProjectId",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "Dynamo59"
   },
   "quote": "ProjectId defaulting to \"Dynamo59\""
  },
  {
   "id": "cluster",
   "kind": "exists",
   "tier": "core",
   "select": "cl",
   "quote": "a recovery control cluster named \"{ProjectId}-Cluster\""
  },
  {
   "id": "cl_name",
   "kind": "attr",
   "tier": "core",
   "select": "cl",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Dynamo59-Cluster"
   },
   "quote": "a recovery control cluster named \"{ProjectId}-Cluster\"",
   "justify": "default ProjectId Dynamo59"
  },
  {
   "id": "cp",
   "kind": "exists",
   "tier": "core",
   "select": "cp",
   "quote": "a control panel named \"{ProjectId}-ControlPanel\" attached to the cluster"
  },
  {
   "id": "cp_name",
   "kind": "attr",
   "tier": "core",
   "select": "cp",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Dynamo59-ControlPanel"
   },
   "quote": "a control panel named \"{ProjectId}-ControlPanel\"",
   "justify": "default ProjectId Dynamo59"
  },
  {
   "id": "cp_cl",
   "kind": "ref",
   "tier": "core",
   "from": "cp",
   "to": "cl",
   "quote": "attached to the cluster"
  },
  {
   "id": "rcs",
   "kind": "exists",
   "tier": "core",
   "select": "rc",
   "min": 2,
   "quote": "two routing controls"
  },
  {
   "id": "rc1",
   "kind": "attr",
   "tier": "core",
   "select": "rc",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Dynamo59-Cell1-us-east-1"
   },
   "quote": "\"{ProjectId}-Cell1-{Region1}\"",
   "justify": "defaults ProjectId Dynamo59 and Region1 us-east-1"
  },
  {
   "id": "rc2",
   "kind": "attr",
   "tier": "core",
   "select": "rc",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Dynamo59-Cell2-us-west-2"
   },
   "quote": "\"{ProjectId}-Cell2-{Region2}\"",
   "justify": "defaults ProjectId Dynamo59 and Region2 us-west-2"
  },
  {
   "id": "rc_cp",
   "tier": "core",
   "quote": "within the control panel",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell1"
       }
      ]
     },
     "to": "cp"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell2"
       }
      ]
     },
     "to": "cp"
    }
   ]
  },
  {
   "id": "sr",
   "kind": "exists",
   "tier": "core",
   "select": "sr",
   "quote": "a safety assertion rule named \"{ProjectId}-MinCellsActive\""
  },
  {
   "id": "sr_name",
   "kind": "attr",
   "tier": "core",
   "select": "sr",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Dynamo59-MinCellsActive"
   },
   "quote": "a safety assertion rule named \"{ProjectId}-MinCellsActive\"",
   "justify": "default ProjectId Dynamo59"
  },
  {
   "id": "sr_wait",
   "kind": "attr",
   "tier": "core",
   "select": "sr",
   "cond": {
    "path": [
     "AssertionRule",
     "WaitPeriodMs"
    ],
    "op": "eq",
    "value": 5000
   },
   "quote": "configured with a 5000 millisecond wait period"
  },
  {
   "id": "sr_type",
   "kind": "attr",
   "tier": "core",
   "select": "sr",
   "cond": {
    "path": [
     "RuleConfig",
     "Type"
    ],
    "op": "eq",
    "value": "ATLEAST"
   },
   "quote": "enforces an \"ATLEAST\" threshold"
  },
  {
   "id": "sr_thr",
   "kind": "attr",
   "tier": "core",
   "select": "sr",
   "cond": {
    "path": [
     "RuleConfig",
     "Threshold"
    ],
    "op": "eq",
    "value": 1
   },
   "quote": "threshold of 1 active cell"
  },
  {
   "id": "sr_ctrls",
   "kind": "attr",
   "tier": "core",
   "select": "sr",
   "cond": {
    "path": [
     "AssertionRule",
     "AssertedControls"
    ],
    "op": "len_gte",
    "value": 2
   },
   "quote": "between the two routing controls",
   "justify": "two routing controls are asserted"
  },
  {
   "id": "sr_rc",
   "tier": "core",
   "quote": "between the two routing controls",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "sr",
     "to": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell1"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "sr",
     "to": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell2"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sr_cp",
   "kind": "ref",
   "tier": "extra",
   "from": "sr",
   "to": "cp"
  },
  {
   "id": "hcs",
   "kind": "exists",
   "tier": "core",
   "select": "hcs",
   "min": 2,
   "quote": "two Route 53 health checks of type \"RECOVERY_CONTROL\""
  },
  {
   "id": "hc_rc",
   "tier": "core",
   "quote": "mapped to each respective routing control",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "hcs",
     "to": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell1"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "hcs",
     "to": {
      "types": [
       "AWS::Route53RecoveryControl::RoutingControl"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "regex",
        "value": "Cell2"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "out_cl",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "cl",
   "quote": "exporting the cluster ARN"
  },
  {
   "id": "out_cp",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "cp",
   "quote": "control panel ARN"
  },
  {
   "id": "out_hc",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "hc",
   "quote": "both health check IDs in the outputs"
  },
  {
   "id": "out_count",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "min": 4,
   "quote": "exporting the cluster ARN, control panel ARN, and both health check IDs in the outputs",
   "justify": "cluster ARN, control panel ARN and two health check IDs are four outputs"
  },
  {
   "id": "x_inv",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "sr",
     "cond": {
      "path": [
       "RuleConfig",
       "Inverted"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "sr",
     "cond": {
      "path": [
       "RuleConfig",
       "Inverted"
      ],
      "op": "absent"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
