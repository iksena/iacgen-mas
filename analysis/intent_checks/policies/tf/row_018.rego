package intent.tf.row_018

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lgs": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": []
  },
  "app": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "cwlg-trilium-log-production-app"
    }
   ]
  },
  "proxy": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "cwlg-trilium-log-production-proxy"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "log_group_app",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "app"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_log_group"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^cwlg-.+-app$"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "names formed from \"cwlg-\" followed by the app, module, and stage values joined by hyphens and ending in \"-app\"",
   "justify": "defaults app=trilium, module=log, stage=production give this name"
  },
  {
   "id": "log_group_proxy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "proxy"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_log_group"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "regex",
        "value": "^cwlg-.+-proxy$"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "ending in \"-app\" or \"-proxy\" respectively",
   "justify": "defaults app=trilium, module=log, stage=production give this name"
  },
  {
   "id": "two_log_groups",
   "kind": "exists",
   "select": "lgs",
   "tier": "core",
   "quote": "creates two Amazon CloudWatch log groups",
   "min": 2
  },
  {
   "id": "retention",
   "kind": "attr",
   "select": "lgs",
   "cond": {
    "path": [
     "retention_in_days"
    ],
    "op": "eq",
    "value": 120
   },
   "tier": "core",
   "quote": "log retention period controlled by a variable named \"log_retention\" defaulting to 120 days",
   "quantifier": "all"
  },
  {
   "id": "var_log_retention",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "log_retention"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 120
     }
    ]
   },
   "tier": "detail",
   "quote": "a variable named \"log_retention\" defaulting to 120 days"
  },
  {
   "id": "var_app_name",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "app_name"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "Trilium Notes"
     }
    ]
   },
   "tier": "detail",
   "quote": "\"app_name\" defaulting to \"Trilium Notes\""
  },
  {
   "id": "var_app",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "app"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "trilium"
     }
    ]
   },
   "tier": "detail",
   "quote": "\"app\" defaulting to \"trilium\""
  },
  {
   "id": "var_module",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "module"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "log"
     }
    ]
   },
   "tier": "detail",
   "quote": "\"module\" defaulting to \"log\""
  },
  {
   "id": "var_stage",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "stage"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "production"
     }
    ]
   },
   "tier": "detail",
   "quote": "\"stage\" defaulting to \"production\""
  },
  {
   "id": "tag_app",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags_all",
       "App"
      ],
      "op": "eq",
      "value": "trilium"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags",
       "App"
      ],
      "op": "eq",
      "value": "trilium"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "apply default tags for App, Module, and Stage derived from these variables"
  },
  {
   "id": "tag_module",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags_all",
       "Module"
      ],
      "op": "eq",
      "value": "log"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags",
       "Module"
      ],
      "op": "eq",
      "value": "log"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "apply default tags for App, Module, and Stage derived from these variables"
  },
  {
   "id": "tag_stage",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags_all",
       "Stage"
      ],
      "op": "eq",
      "value": "production"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "lgs",
     "cond": {
      "path": [
       "tags",
       "Stage"
      ],
      "op": "eq",
      "value": "production"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "apply default tags for App, Module, and Stage derived from these variables"
  },
  {
   "id": "name_tag_app",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "app",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "cwlg-trilium-log-production-app"
     }
    },
    {
     "kind": "attr",
     "select": "app",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "cwlg-trilium-log-production-app"
     }
    }
   ],
   "tier": "detail",
   "quote": "a Name tag matching each respective log group name",
   "justify": "Name tag equals the group name derived from the defaults"
  },
  {
   "id": "name_tag_proxy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "proxy",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "cwlg-trilium-log-production-proxy"
     }
    },
    {
     "kind": "attr",
     "select": "proxy",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "cwlg-trilium-log-production-proxy"
     }
    }
   ],
   "tier": "detail",
   "quote": "a Name tag matching each respective log group name",
   "justify": "Name tag equals the group name derived from the defaults"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
