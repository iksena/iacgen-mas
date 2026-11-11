package intent.cfn.row_069

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "any": {
   "types": [
    "AWS::IoTSiteWise::AssetModel"
   ],
   "where": []
  },
  "turbine": {
   "types": [
    "AWS::IoTSiteWise::AssetModel"
   ],
   "where": [
    {
     "path": [
      "AssetModelProperties",
      "*",
      "Type",
      "TypeName"
     ],
     "op": "eq",
     "value": "Measurement"
    },
    {
     "path": [
      "AssetModelHierarchies",
      "*"
     ],
     "op": "absent"
    }
   ]
  },
  "farm": {
   "types": [
    "AWS::IoTSiteWise::AssetModel"
   ],
   "where": [
    {
     "path": [
      "AssetModelHierarchies"
     ],
     "op": "present"
    }
   ]
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_models",
   "kind": "exists",
   "select": "any",
   "tier": "core",
   "quote": "creates two IoT SiteWise asset models",
   "min": 2,
   "max": 2
  },
  {
   "id": "turbine_model",
   "kind": "exists",
   "select": "turbine",
   "tier": "core",
   "quote": "a Turbine Asset Model",
   "justify": "the turbine model is the one with measurements"
  },
  {
   "id": "turbine_name",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelName"
    ],
    "op": "regex",
    "value": "(?i)turbine"
   },
   "tier": "detail",
   "quote": "a Turbine Asset Model"
  },
  {
   "id": "farm_model",
   "kind": "exists",
   "select": "farm",
   "tier": "core",
   "quote": "a Wind Farm Asset Model",
   "justify": "the wind farm model is the one with a hierarchy of child models"
  },
  {
   "id": "farm_name",
   "kind": "attr",
   "select": "farm",
   "cond": {
    "path": [
     "AssetModelName"
    ],
    "op": "regex",
    "value": "(?i)wind\\s*farm"
   },
   "tier": "detail",
   "quote": "a Wind Farm Asset Model"
  },
  {
   "id": "turbine_attributes",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*",
     "Type",
     "TypeName"
    ],
    "op": "eq",
    "value": "Attribute"
   },
   "tier": "core",
   "quote": "with attributes, measurements, transforms"
  },
  {
   "id": "turbine_transforms",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*",
     "Type",
     "TypeName"
    ],
    "op": "eq",
    "value": "Transform"
   },
   "tier": "core",
   "quote": "with attributes, measurements, transforms"
  },
  {
   "id": "turbine_overdrive",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)overdrive"
     },
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Transform"
     },
     {
      "path": [
       "Type",
       "Transform",
       "Expression"
      ],
      "op": "regex",
      "value": "(?i)(gte?\\s*\\(\\s*\\w+\\s*,\\s*3(\\.0+)?\\s*\\)|\\w+\\s*>=?\\s*3(\\.0+)?([^0-9.]|$))"
     },
     {
      "path": [
       "Type",
       "Transform"
      ],
      "op": "regex",
      "value": "(?i)torque"
     }
    ]
   },
   "tier": "core",
   "quote": "an overdrive state transform that triggers when torque exceeds 3",
   "justify": "exceeds 3 = a greater-than comparison against 3"
  },
  {
   "id": "turbine_avg_wind_speed",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Metric"
     },
     {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)wind\\s*speed"
     },
     {
      "path": [
       "Type",
       "Metric",
       "Expression"
      ],
      "op": "regex",
      "value": "(?i)avg\\s*\\("
     },
     {
      "path": [
       "Type",
       "Metric",
       "Window",
       "Tumbling",
       "Interval"
      ],
      "op": "regex",
      "value": "(?i)^(5m|5 minutes?|300s?)$"
     }
    ]
   },
   "tier": "core",
   "quote": "metrics computed over a 5-minute tumbling window (including average wind speed",
   "justify": "5-minute tumbling window; average = avg()"
  },
  {
   "id": "turbine_overdrive_time",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Metric"
     },
     {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)overdrive.*time|time.*overdrive"
     },
     {
      "path": [
       "Type",
       "Metric",
       "Window",
       "Tumbling",
       "Interval"
      ],
      "op": "regex",
      "value": "(?i)^(5m|5 minutes?|300s?)$"
     }
    ]
   },
   "tier": "core",
   "quote": "overdrive state time",
   "justify": "5-minute tumbling window"
  },
  {
   "id": "turbine_avg_power",
   "kind": "attr",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Metric"
     },
     {
      "path": [
       "Name"
      ],
      "op": "regex",
      "value": "(?i)power"
     },
     {
      "path": [
       "Type",
       "Metric",
       "Expression"
      ],
      "op": "regex",
      "value": "(?i)avg\\s*\\("
     },
     {
      "path": [
       "Type",
       "Metric",
       "Window",
       "Tumbling",
       "Interval"
      ],
      "op": "regex",
      "value": "(?i)^(5m|5 minutes?|300s?)$"
     }
    ]
   },
   "tier": "core",
   "quote": "and average power",
   "justify": "5-minute tumbling window; average = avg()"
  },
  {
   "id": "farm_attributes",
   "kind": "attr",
   "select": "farm",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*",
     "Type",
     "TypeName"
    ],
    "op": "eq",
    "value": "Attribute"
   },
   "tier": "core",
   "quote": "a Wind Farm Asset Model with its own attributes"
  },
  {
   "id": "farm_rollup_metrics",
   "kind": "attr",
   "select": "farm",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Metric"
     },
     {
      "path": [
       "Type",
       "Metric",
       "Expression"
      ],
      "op": "regex",
      "value": "(?i)sum\\s*\\("
     },
     {
      "path": [
       "Type",
       "Metric",
       "Variables",
       "*",
       "Value"
      ],
      "op": "regex",
      "value": "Hierarchy"
     },
     {
      "path": [
       "Type",
       "Metric",
       "Window",
       "Tumbling",
       "Interval"
      ],
      "op": "regex",
      "value": "(?i)^(5m|5 minutes?|300s?)$"
     }
    ]
   },
   "tier": "core",
   "quote": "metrics that roll up totals from the turbines over the same 5-minute window",
   "justify": "totals = sum() over the hierarchy; 5-minute tumbling window"
  },
  {
   "id": "hierarchy_links_turbine",
   "kind": "ref",
   "from": "farm",
   "to": "turbine",
   "tier": "core",
   "quote": "linked to the Turbine Asset Model via a hierarchy"
  },
  {
   "id": "outputs",
   "kind": "exists",
   "select": "outs",
   "tier": "detail",
   "quote": "the template should output the identifiers of both asset models and the identifier of the hierarchy association between them",
   "min": 3,
   "justify": "two model ids plus the hierarchy id = three outputs"
  },
  {
   "id": "output_hierarchy",
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)hierarch"
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
         "description"
        ],
        "op": "regex",
        "value": "(?i)hierarch"
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
        "value": "(?i)hierarch"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "the identifier of the hierarchy association between them"
  },
  {
   "id": "output_turbine",
   "kind": "ref",
   "from": "outs",
   "to": "turbine",
   "tier": "detail",
   "quote": "output the identifiers of both asset models"
  },
  {
   "id": "output_farm",
   "kind": "ref",
   "from": "outs",
   "to": "farm",
   "tier": "detail",
   "quote": "output the identifiers of both asset models"
  },
  {
   "id": "x_measurement_unit",
   "kind": "attr",
   "tier": "extra",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Measurement"
     },
     {
      "path": [
       "Unit"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "x_transform_vars",
   "kind": "attr",
   "tier": "extra",
   "select": "turbine",
   "cond": {
    "path": [
     "AssetModelProperties",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Type",
       "TypeName"
      ],
      "op": "eq",
      "value": "Transform"
     },
     {
      "path": [
       "Type",
       "Transform",
       "Variables",
       "*",
       "Name"
      ],
      "op": "present"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
