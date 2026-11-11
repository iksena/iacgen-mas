package intent.cfn.row_097

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "subs": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::SNS::Subscription"
    }
   ]
  },
  "https": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::SNS::Subscription"
    },
    {
     "path": [
      "properties",
      "Protocol"
     ],
     "op": "eq",
     "value": "https"
    }
   ]
  },
  "params": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "sub_email",
   "tier": "core",
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
      "value": "AWS::SNS::Subscription"
     },
     {
      "path": [
       "properties",
       "Protocol"
      ],
      "op": "eq",
      "value": "email"
     }
    ]
   },
   "quote": "an email address",
   "justify": "email subscription protocol"
  },
  {
   "id": "sub_sqs",
   "tier": "core",
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
      "value": "AWS::SNS::Subscription"
     },
     {
      "path": [
       "properties",
       "Protocol"
      ],
      "op": "eq",
      "value": "sqs"
     }
    ]
   },
   "quote": "an SQS queue ARN",
   "justify": "sqs subscription protocol"
  },
  {
   "id": "sub_lambda",
   "tier": "core",
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
      "value": "AWS::SNS::Subscription"
     },
     {
      "path": [
       "properties",
       "Protocol"
      ],
      "op": "eq",
      "value": "lambda"
     }
    ]
   },
   "quote": "a Lambda function ARN",
   "justify": "lambda subscription protocol"
  },
  {
   "id": "sub_https",
   "tier": "core",
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
      "value": "AWS::SNS::Subscription"
     },
     {
      "path": [
       "properties",
       "Protocol"
      ],
      "op": "eq",
      "value": "https"
     }
    ]
   },
   "quote": "an HTTPS endpoint URL"
  },
  {
   "id": "subs_conditional",
   "tier": "core",
   "kind": "attr",
   "select": "subs",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quantifier": "all",
   "quote": "conditionally create each corresponding SNS subscription only when its respective parameter differs from a sentinel default value"
  },
  {
   "id": "https_backoff",
   "tier": "core",
   "kind": "attr",
   "select": "https",
   "cond": {
    "path": [
     "properties",
     "DeliveryPolicy"
    ],
    "op": "regex",
    "value": "(?i)exponential"
   },
   "quote": "the HTTPS subscription should include a delivery policy configured with an exponential backoff retry strategy"
  },
  {
   "id": "topic_arn_from_input",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "join",
     "from": "subs",
     "from_path": [
      "properties",
      "TopicArn"
     ],
     "to": "params",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "attr",
     "select": "subs",
     "cond": {
      "path": [
       "properties",
       "TopicArn"
      ],
      "op": "regex",
      "value": "^<param:"
     }
    }
   ],
   "quote": "taking the SNS topic ARN as a required input configuration value"
  },
  {
   "id": "topic_not_provisioned",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "type"
    ],
    "op": "none_eq",
    "value": "AWS::SNS::Topic"
   },
   "quote": "an identifier passed in, not something the template provisions"
  },
  {
   "id": "endpoints_from_parameters",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "join",
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
        "value": "AWS::SNS::Subscription"
       },
       {
        "path": [
         "properties",
         "Protocol"
        ],
        "op": "eq",
        "value": "email"
       }
      ]
     },
     "from_path": [
      "properties",
      "Endpoint"
     ],
     "to": "params",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
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
        "value": "AWS::SNS::Subscription"
       },
       {
        "path": [
         "properties",
         "Protocol"
        ],
        "op": "eq",
        "value": "sqs"
       }
      ]
     },
     "from_path": [
      "properties",
      "Endpoint"
     ],
     "to": "params",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
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
        "value": "AWS::SNS::Subscription"
       },
       {
        "path": [
         "properties",
         "Protocol"
        ],
        "op": "eq",
        "value": "lambda"
       }
      ]
     },
     "from_path": [
      "properties",
      "Endpoint"
     ],
     "to": "params",
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "join",
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
        "value": "AWS::SNS::Subscription"
       },
       {
        "path": [
         "properties",
         "Protocol"
        ],
        "op": "eq",
        "value": "https"
       }
      ]
     },
     "from_path": [
      "properties",
      "Endpoint"
     ],
     "to": "params",
     "to_path": [
      "default"
     ]
    }
   ],
   "quote": "optional parameters for an email address, an SQS queue ARN, a Lambda function ARN, and an HTTPS endpoint URL"
  },
  {
   "id": "endpoints_not_provisioned",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "AWS::SQS::Queue"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "AWS::Lambda::Function"
     }
    }
   ],
   "quote": "each also supplied as plain identifier/configuration values rather than resources the template builds"
  },
  {
   "id": "x_delivery_retries",
   "tier": "extra",
   "kind": "attr",
   "select": "https",
   "cond": {
    "path": [
     "properties",
     "DeliveryPolicy"
    ],
    "op": "regex",
    "value": "numRetries"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
