package intent.cfn.row_220

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "res_webhooks": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "eq",
     "value": "webhooks"
    }
   ]
  },
  "post_method": {
   "types": [
    "AWS::ApiGateway::Method"
   ],
   "where": [
    {
     "path": [
      "HttpMethod"
     ],
     "op": "eq",
     "value": "POST"
    }
   ]
  },
  "stage": {
   "types": [
    "AWS::ApiGateway::Stage"
   ],
   "where": [
    {
     "path": [
      "StageName"
     ],
     "op": "eq",
     "value": "prod"
    }
   ]
  },
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "role": {
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
     "op": "eq",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "perm": {
   "types": [
    "AWS::Lambda::Permission"
   ],
   "where": [
    {
     "path": [
      "Principal"
     ],
     "op": "eq",
     "value": "apigateway.amazonaws.com"
    }
   ]
  },
  "alarm": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Errors"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "rest_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "an API Gateway REST API"
  },
  {
   "id": "post_webhooks",
   "kind": "ref",
   "from": "post_method",
   "to": "res_webhooks",
   "tier": "core",
   "quote": "a POST /webhooks endpoint"
  },
  {
   "id": "prod_stage",
   "kind": "any_of",
   "tier": "core",
   "quote": "deployed to a prod stage",
   "checks": [
    {
     "kind": "ref",
     "from": "stage",
     "to": "api"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "eq",
        "value": "prod"
       }
      ]
     },
     "to": "api"
    }
   ]
  },
  {
   "id": "lambda_function",
   "kind": "exists",
   "select": "fn",
   "tier": "core",
   "quote": "backed by a Lambda function"
  },
  {
   "id": "method_backed_by_lambda",
   "kind": "any_of",
   "tier": "core",
   "quote": "backed by a Lambda function",
   "checks": [
    {
     "kind": "ref",
     "from": "post_method",
     "to": "fn"
    },
    {
     "kind": "attr",
     "select": "post_method",
     "cond": {
      "path": [
       "Integration",
       "Uri"
      ],
      "op": "regex",
      "value": "(?i):lambda:path/|:function:"
     }
    }
   ]
  },
  {
   "id": "lambda_role",
   "kind": "ref",
   "from": "fn",
   "to": "role",
   "tier": "core",
   "quote": "the Lambda function's execution role"
  },
  {
   "id": "role_sns_publish",
   "kind": "any_of",
   "tier": "core",
   "quote": "with permission to publish to that topic",
   "justify": "publish to an SNS topic means sns:Publish",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "sns:Publish"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "sns:Publish"
         }
        ]
       }
      ]
     },
     "bidirectional": true
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonSNSFullAccess"
     }
    }
   ]
  },
  {
   "id": "sns_topic_or_parameter",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::SNS::Topic"
      ],
      "where": []
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)topic"
       }
      ]
     }
    }
   ],
   "quote": "an SNS topic that the stack also creates",
   "justify": "what the prompt and the GT both guarantee: a topic is created or taken as input"
  },
  {
   "id": "apigw_invoke_permission",
   "kind": "ref",
   "from": "perm",
   "to": "fn",
   "tier": "core",
   "quote": "the permission allowing API Gateway to invoke the function"
  },
  {
   "id": "error_alarm",
   "kind": "exists",
   "select": "alarm",
   "tier": "core",
   "quote": "a CloudWatch alarm that triggers whenever the function's invocation errors"
  },
  {
   "id": "alarm_on_function",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the function's invocation errors",
   "checks": [
    {
     "kind": "ref",
     "from": "alarm",
     "to": "fn"
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "Dimensions",
      "*",
      "Value"
     ],
     "to": "fn",
     "to_path": [
      "FunctionName"
     ]
    }
   ]
  },
  {
   "id": "alarm_threshold",
   "kind": "any_of",
   "tier": "detail",
   "quote": "exceed zero",
   "justify": "errors exceed zero means > 0, or >= 1 because the count is whole",
   "checks": [
    {
     "kind": "attr",
     "select": "alarm",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 0
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "alarm",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "alarm_period",
   "kind": "attr",
   "select": "alarm",
   "cond": {
    "path": [
     "Period"
    ],
    "op": "eq",
    "value": 60
   },
   "tier": "detail",
   "quote": "within a one-minute period",
   "justify": "one minute is 60 seconds"
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": [
     {
      "path": [
       "LogGroupName"
      ],
      "op": "regex",
      "value": "/aws/lambda/"
     }
    ]
   },
   "tier": "core",
   "quote": "the function's log group",
   "justify": "a Lambda function logs to /aws/lambda/<name>"
  },
  {
   "id": "squarespace_token_parameter",
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
      "value": "(?i)squarespace|token"
     }
    ]
   },
   "tier": "core",
   "quote": "The Squarespace API token"
  },
  {
   "id": "stripe_secret_parameter",
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
      "value": "(?i)stripe|signing"
     }
    ]
   },
   "tier": "core",
   "quote": "the Stripe webhook signing secret"
  },
  {
   "id": "required_params",
   "kind": "all_of",
   "tier": "detail",
   "quote": "should be accepted as required input parameters",
   "justify": "a required parameter has no default",
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
        "value": "(?i)squarespace|token"
       },
       {
        "path": [
         "default"
        ],
        "op": "absent"
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)stripe|signing"
       },
       {
        "path": [
         "default"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_alarm_namespace",
   "kind": "attr",
   "select": "alarm",
   "cond": {
    "path": [
     "Namespace"
    ],
    "op": "eq",
    "value": "AWS/Lambda"
   },
   "tier": "extra"
  },
  {
   "id": "x_apigw_post_integration",
   "kind": "attr",
   "select": "post_method",
   "cond": {
    "path": [
     "Integration",
     "Type"
    ],
    "op": "eq",
    "value": "AWS_PROXY"
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_apigateway_deployment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApiGateway::Deployment"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
