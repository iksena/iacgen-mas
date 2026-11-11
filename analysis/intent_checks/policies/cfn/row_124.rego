package intent.cfn.row_124

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cb": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)callback"
    }
   ]
  },
  "lambda_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)^lambda\\.amazonaws\\.com$"
    }
   ]
  },
  "retention_values": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "allowed_values",
      "*"
     ],
     "op": "in",
     "value": [
      1,
      3,
      5,
      7,
      14,
      30,
      60,
      90,
      120,
      150,
      180,
      365,
      400,
      545,
      731,
      1096,
      1827,
      2192,
      2557,
      2922,
      3288,
      3653
     ],
     "every": true
    },
    {
     "path": [
      "allowed_values",
      "*"
     ],
     "op": "eq",
     "value": 3653
    }
   ]
  }
 },
 "checks": [
  {
   "id": "five_functions",
   "kind": "exists",
   "tier": "core",
   "quote": "creates five Lambda functions",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "min": 5
  },
  {
   "id": "five_usecallbacks_params",
   "kind": "exists",
   "tier": "core",
   "quote": "(five separate parameters, one per function)",
   "justify": "five functions each with its own parameter",
   "select": "cb",
   "min": 5
  },
  {
   "id": "usecallbacks_default_no",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to no",
   "select": "cb",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "no"
   },
   "quantifier": "all"
  },
  {
   "id": "usecallbacks_allowed",
   "kind": "all_of",
   "tier": "core",
   "quote": "restricted to allowed values of no or yes",
   "checks": [
    {
     "kind": "attr",
     "select": "cb",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "no"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "cb",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "yes"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "cb",
     "cond": {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "in",
      "value": [
       "no",
       "yes"
      ],
      "every": true
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "shared_role",
   "kind": "exists",
   "tier": "core",
   "quote": "a shared IAM role granting basic Lambda execution permissions",
   "select": "lambda_role",
   "min": 1,
   "max": 1,
   "justify": "a shared role means one role for the functions"
  },
  {
   "id": "functions_use_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "a shared IAM role",
   "from": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  },
  {
   "id": "basic_execution",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting basic Lambda execution permissions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "contains",
      "value": "AWSLambdaBasicExecutionRole"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
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
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
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
    }
   ]
  },
  {
   "id": "log_groups",
   "kind": "exists",
   "tier": "core",
   "quote": "pre-created CloudWatch log groups",
   "justify": "plural log groups, one per function",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   },
   "min": 2
  },
  {
   "id": "retention_default_7",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to 7 days",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 7
   },
   "quantifier": "all"
  },
  {
   "id": "retention_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a configurable retention period parameter",
   "checks": [
    {
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
        "op": "regex",
        "value": "(?i)retention"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 7
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "allowed_values",
         "*"
        ],
        "op": "in",
        "value": [
         1,
         3,
         5,
         7,
         14,
         30,
         60,
         90,
         120,
         150,
         180,
         365,
         400,
         545,
         731,
         1096,
         1827,
         2192,
         2557,
         2922,
         3288,
         3653
        ],
        "every": true
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 7
       }
      ]
     }
    }
   ]
  },
  {
   "id": "retention_allowed",
   "kind": "exists",
   "tier": "detail",
   "quote": "restricted to the standard CloudWatch Logs allowed retention values (such as 1, 3, 5, 7, 14, 30, 60, 90, and so on up to 3653)",
   "select": "retention_values",
   "justify": "the standard CloudWatch Logs retention values; a subset is still restricted to them"
  },
  {
   "id": "function_name_prefix",
   "kind": "attr",
   "tier": "core",
   "quote": "named using a mapping-defined prefix \"LambdaFunctionInvokerHookTest\" followed by a sequential number",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "regex",
    "value": "^LambdaFunctionInvokerHookTest[-_]?[0-9]+$"
   },
   "quantifier": "all"
  },
  {
   "id": "function_names_distinct",
   "kind": "exists",
   "tier": "detail",
   "quote": "followed by a sequential number",
   "justify": "five functions get five distinct sequential names",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "distinct_path": [
    "FunctionName"
   ],
   "min": 5
  },
  {
   "id": "functions_take_callback_setting",
   "kind": "attr",
   "tier": "detail",
   "quote": "the template should allow independent callback settings per function",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Environment",
     "Variables",
     "*"
    ],
    "op": "in",
    "value": [
     "no",
     "yes"
    ]
   },
   "quantifier": "all"
  },
  {
   "id": "x_runtime_python",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Lambda::Function"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "regex",
    "value": "^python3"
   },
   "quantifier": "all"
  },
  {
   "id": "x_log_group_path",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "LogGroupName"
    ],
    "op": "regex",
    "value": "^/aws/lambda/"
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
