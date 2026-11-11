package intent.tf.row_210

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": []
  },
  "key": {
   "types": [
    "aws_iam_access_key"
   ],
   "where": []
  },
  "pols": {
   "types": [
    "aws_iam_policy",
    "aws_iam_user_policy"
   ],
   "where": []
  },
  "d_pols": {
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
      "aws_iam_user_policy"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "user_exists",
   "kind": "exists",
   "tier": "core",
   "select": "user",
   "quote": "a dedicated IAM user"
  },
  {
   "id": "user_path",
   "kind": "attr",
   "tier": "core",
   "select": "user",
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quote": "IAM user at root path \"/\""
  },
  {
   "id": "user_name",
   "kind": "attr",
   "tier": "core",
   "select": "user",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "postman-user"
   },
   "quote": "defaulting in name to \"postman-user\""
  },
  {
   "id": "access_key",
   "kind": "exists",
   "tier": "core",
   "select": "key",
   "quote": "a set of IAM access keys"
  },
  {
   "id": "key_user",
   "kind": "ref",
   "tier": "detail",
   "from": "key",
   "to": "user",
   "quote": "a set of IAM access keys"
  },
  {
   "id": "apigw_get",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "apigateway:GET"
     }
    },
    {
     "kind": "attr",
     "select": "d_pols",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "apigateway:GET"
     }
    },
    {
     "kind": "ref",
     "from": "d_pols",
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "apigateway:GET"
       }
      ]
     }
    }
   ],
   "quote": "(\"apigateway:GET\")"
  },
  {
   "id": "cw_getmetricdata",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cloudwatch:GetMetricData"
     }
    },
    {
     "kind": "attr",
     "select": "d_pols",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "cloudwatch:GetMetricData"
     }
    },
    {
     "kind": "ref",
     "from": "d_pols",
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "cloudwatch:GetMetricData"
       }
      ]
     }
    }
   ],
   "quote": "(\"cloudwatch:GetMetricData\", \"cloudwatch:ListMetrics\")"
  },
  {
   "id": "cw_listmetrics",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cloudwatch:ListMetrics"
     }
    },
    {
     "kind": "attr",
     "select": "d_pols",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "cloudwatch:ListMetrics"
     }
    },
    {
     "kind": "ref",
     "from": "d_pols",
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "cloudwatch:ListMetrics"
       }
      ]
     }
    }
   ],
   "quote": "(\"cloudwatch:GetMetricData\", \"cloudwatch:ListMetrics\")"
  },
  {
   "id": "global_resources",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "pols",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"?resources?\"?:\\s*\\[?\"?\\*"
     }
    },
    {
     "kind": "attr",
     "select": "d_pols",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"?resources?\"?:\\s*\\[?\"?\\*"
     }
    },
    {
     "kind": "ref",
     "from": "d_pols",
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)\"?resources?\"?:\\s*\\[?\"?\\*"
       }
      ]
     }
    }
   ],
   "quote": "grant global read-only access",
   "justify": "global access means Resource *"
  },
  {
   "id": "policies_attached",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": "user"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_user_policy"
      ],
      "where": []
     }
    }
   ],
   "quote": "attaching policies that grant global read-only access"
  },
  {
   "id": "cognito_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "cognito_user_pool_arn"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   },
   "quote": "an optional cognito_user_pool_arn variable (defaulting to an empty string)"
  },
  {
   "id": "cognito_policy_declared",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM policy granting \"cognito-idp:AdminInitiateAuth\" permissions",
   "checks": [
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cognito-idp:AdminInitiateAuth"
       }
      ]
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       }
      ]
     },
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "cognito-idp:AdminInitiateAuth"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cognito_conditional",
   "kind": "any_of",
   "tier": "core",
   "quote": "the template must conditionally create and attach an IAM policy",
   "checks": [
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cognito-idp:AdminInitiateAuth"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i)cognito"
       }
      ]
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i)cognito"
       }
      ]
     },
     "to": {
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
         "properties"
        ],
        "op": "regex",
        "value": "cognito-idp:AdminInitiateAuth"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cognito_scoped",
   "kind": "any_of",
   "tier": "detail",
   "quote": "specifically scoped to that Cognito user pool ARN",
   "checks": [
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
        "op": "in",
        "value": [
         "aws_iam_policy",
         "aws_iam_user_policy"
        ]
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?s)cognito-idp:AdminInitiateAuth.{0,300}var\\.cognito_user_pool_arn|var\\.cognito_user_pool_arn.{0,300}cognito-idp:AdminInitiateAuth"
       }
      ]
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "eq",
          "value": "cognito-idp:AdminInitiateAuth"
         },
         {
          "path": [
           "resources"
          ],
          "op": "len_gte",
          "value": 1
         },
         {
          "path": [
           "resources",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cognito_attach_conditional",
   "kind": "exists",
   "tier": "detail",
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
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment",
       "aws_iam_user_policy"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "gate"
      ],
      "op": "regex",
      "value": "(?i)cognito"
     }
    ]
   },
   "quote": "conditionally create and attach an IAM policy"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
