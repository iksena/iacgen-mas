package intent.tf.row_334

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "log_group",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "quote": "creates a CloudWatch Logs log group"
  },
  {
   "id": "retention_7",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudwatch_log_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "retention_in_days"
    ],
    "op": "eq",
    "value": 7
   },
   "quote": "a 7-day retention period"
  },
  {
   "id": "random_pet",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_pet"
      ],
      "where": []
     }
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
        "value": "random_pet"
       }
      ]
     }
    }
   ],
   "quote": "generated random pet-name suffix",
   "justify": "a random pet-name is the random_pet resource"
  },
  {
   "id": "iam_policy",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_policy",
     "aws_iam_role_policy",
     "aws_iam_user_policy",
     "aws_iam_group_policy"
    ],
    "where": []
   },
   "quote": "along with an IAM policy"
  },
  {
   "id": "act_create_stream",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Create\\*|CreateLogStream)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Create\\*|CreateLogStream)"
     }
    },
    {
     "kind": "attr",
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "logs:(\\*|Create\\*|CreateLogStream)"
     }
    }
   ],
   "quote": "creating log streams",
   "justify": "log action named in the prompt"
  },
  {
   "id": "act_describe_streams",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Describe\\*|DescribeLogStreams)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Describe\\*|DescribeLogStreams)"
     }
    },
    {
     "kind": "attr",
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "logs:(\\*|Describe\\*|DescribeLogStreams)"
     }
    }
   ],
   "quote": "describing log streams",
   "justify": "log action named in the prompt"
  },
  {
   "id": "act_put_events",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_user_policy",
       "aws_iam_group_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Put\\*|PutLogEvents)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(\\*|Put\\*|PutLogEvents)"
     }
    },
    {
     "kind": "attr",
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement"
      ],
      "op": "regex",
      "value": "logs:(\\*|Put\\*|PutLogEvents)"
     }
    }
   ],
   "quote": "putting log events",
   "justify": "log action named in the prompt"
  },
  {
   "id": "scoped_to_group",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_user_policy",
         "aws_iam_group_policy"
        ]
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "^(?s)(?:[^'\"]|['\"]+(?:[^'\"*]|\\*[^'\"]))*(?:['\"]+\\*?)?$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_cloudwatch_log_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*",
         "resources",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       }
      ]
     },
     "to": {
      "types": [
       "aws_cloudwatch_log_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "only on that log group"
  },
  {
   "id": "extra_type_aws_cloudwatch_log_metric_filter",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_cloudwatch_log_metric_filter"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
