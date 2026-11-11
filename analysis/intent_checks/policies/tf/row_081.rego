package intent.tf.row_081

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "aws_api_gateway_rest_api"
   ],
   "where": []
  },
  "method": {
   "types": [
    "aws_api_gateway_method"
   ],
   "where": []
  },
  "integ": {
   "types": [
    "aws_api_gateway_integration"
   ],
   "where": []
  },
  "topic": {
   "types": [
    "aws_sns_topic"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "rest_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "a REST API Gateway endpoint"
  },
  {
   "id": "method_post",
   "kind": "attr",
   "select": "method",
   "cond": {
    "path": [
     "http_method"
    ],
    "op": "eq",
    "value": "POST"
   },
   "tier": "core",
   "quote": "publishes incoming POST requests"
  },
  {
   "id": "integ_sns",
   "kind": "attr",
   "select": "integ",
   "cond": {
    "path": [
     "uri"
    ],
    "op": "regex",
    "value": "(?i):sns:"
   },
   "tier": "core",
   "quote": "publishes incoming POST requests directly to an SNS topic"
  },
  {
   "id": "integ_topic",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "integ",
     "to": "topic"
    },
    {
     "kind": "attr",
     "select": "integ",
     "cond": {
      "path": [
       "request_templates"
      ],
      "op": "regex",
      "value": "event-topic"
     }
    },
    {
     "kind": "attr",
     "select": "integ",
     "cond": {
      "path": [
       "request_parameters"
      ],
      "op": "regex",
      "value": "event-topic"
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
        "value": "aws_api_gateway_integration"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "request_templates"
      ],
      "op": "regex",
      "value": "(?i)local\\.[a-z0-9_]*(sns|topic)"
     }
    }
   ],
   "tier": "core",
   "quote": "directly to an SNS topic named event-topic"
  },
  {
   "id": "topic",
   "kind": "exists",
   "select": "topic",
   "tier": "core",
   "quote": "an SNS topic named event-topic"
  },
  {
   "id": "topic_name",
   "kind": "attr",
   "select": "topic",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "event-topic"
   },
   "tier": "core",
   "quote": "an SNS topic named event-topic"
  },
  {
   "id": "kms",
   "kind": "exists",
   "select": "kms",
   "tier": "core",
   "quote": "a dedicated customer-managed KMS key"
  },
  {
   "id": "topic_kms",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "topic",
     "to": "kms"
    },
    {
     "kind": "ref",
     "from": "topic",
     "to": {
      "types": [
       "aws_kms_alias"
      ],
      "where": []
     }
    }
   ],
   "tier": "core",
   "quote": "encrypted with a dedicated customer-managed KMS key"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with key rotation"
  },
  {
   "id": "role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "an IAM role that grants the API Gateway permission"
  },
  {
   "id": "role_trust",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "apigateway\\.amazonaws\\.com"
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
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "apigateway\\.amazonaws\\.com"
     }
    }
   ],
   "tier": "core",
   "quote": "an IAM role that grants the API Gateway permission to publish"
  },
  {
   "id": "role_publish",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy",
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)sns:(publish|\\*)([^A-Za-z0-9_]|$)"
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
         "aws_iam_role_policy",
         "aws_iam_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)sns:(publish|\\*)([^A-Za-z0-9_]|$)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)AmazonSNS(Full)?Access"
     }
    }
   ],
   "tier": "core",
   "quote": "permission to publish to that topic"
  },
  {
   "id": "role_policy_attached",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": "role"
    }
   ],
   "tier": "detail",
   "quote": "an IAM role that grants the API Gateway permission to publish to that topic"
  },
  {
   "id": "integ_role",
   "kind": "ref",
   "from": "integ",
   "to": "role",
   "tier": "core",
   "quote": "using an IAM role"
  },
  {
   "id": "integ_form",
   "kind": "attr",
   "select": "integ",
   "cond": {
    "path": [
     "request_parameters"
    ],
    "op": "regex",
    "value": "x-www-form-urlencoded"
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_api_gateway_integration_response",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_api_gateway_integration_response"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_api_gateway_method_response",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_api_gateway_method_response"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_api_gateway_resource",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_api_gateway_resource"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
