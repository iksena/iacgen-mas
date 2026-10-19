package intent.cfn.row_257

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "py_fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": [
    {
     "path": [
      "Runtime"
     ],
     "op": "regex",
     "value": "^python3"
    }
   ]
  },
  "api": {
   "types": [
    "AWS::ApiGatewayV2::Api"
   ],
   "where": []
  },
  "pool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "topic": {
   "types": [
    "AWS::SNS::Topic"
   ],
   "where": []
  },
  "log_group": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
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
     "value": "ExecutionsFailed"
    }
   ]
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "kms_key_alias",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   },
   "to": "key",
   "tier": "core",
   "quote": "a customer managed KMS key with a friendly alias"
  },
  {
   "id": "three_tables",
   "kind": "exists",
   "select": "table",
   "min": 3,
   "tier": "core",
   "quote": "three DynamoDB tables holding customer profiles, per channel rate limits and message delivery tracking"
  },
  {
   "id": "assets_bucket",
   "kind": "exists",
   "select": "bucket",
   "tier": "core",
   "quote": "an S3 bucket for campaign assets"
  },
  {
   "id": "data_stores_encrypted_with_key",
   "kind": "all_of",
   "tier": "core",
   "quote": "used to encrypt its data stores",
   "checks": [
    {
     "kind": "ref",
     "from": "table",
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": "key"
    }
   ]
  },
  {
   "id": "all_tables_cmk",
   "kind": "attr",
   "select": "table",
   "quantifier": "all",
   "cond": {
    "path": [
     "SSESpecification",
     "KMSMasterKeyId"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "used to encrypt its data stores"
  },
  {
   "id": "state_machine_invokes_lambdas",
   "kind": "ref",
   "from": "sm",
   "to": "py_fn",
   "tier": "core",
   "quote": "a state machine running a pipeline of Python Lambda functions"
  },
  {
   "id": "python_functions_count",
   "kind": "exists",
   "select": "py_fn",
   "min": 7,
   "tier": "detail",
   "quote": "parse the instruction, segment the target customers, predict the best channel for each of them, run a safety check over the generated content, adapt that content per channel, deliver the messages and finally record the results",
   "justify": "the prompt enumerates seven pipeline steps; one function per step (steps may be merged with helpers, so no higher bound)"
  },
  {
   "id": "pipeline_seven_tasks",
   "kind": "any_of",
   "tier": "detail",
   "quote": "parse the instruction, segment the target customers, predict the best channel for each of them, run a safety check over the generated content, adapt that content per channel, deliver the messages and finally record the results",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)(type\\W+task[\\s\\S]*){7}"
     }
    },
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)(type\\W+task[\\s\\S]*){7}"
     }
    }
   ],
   "justify": "the prompt enumerates seven pipeline steps (parse, segment, predict, safety, adapt, deliver, record)"
  },
  {
   "id": "bedrock_model_parameter",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "(?i)(anthropic|amazon|meta|mistral|cohere|ai21|deepseek|openai|qwen)\\.[a-z]"
   },
   "tier": "detail",
   "quote": "an Amazon Bedrock model chosen through a parameter"
  },
  {
   "id": "bedrock_invoke_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the generative steps calling an Amazon Bedrock model",
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
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)bedrock:(\\*|invokemodel)"
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
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)bedrock:(\\*|invokemodel)"
     }
    }
   ]
  },
  {
   "id": "http_api_to_functions",
   "kind": "any_of",
   "tier": "core",
   "quote": "a campaign launcher function and a campaign status function behind an HTTP API",
   "checks": [
    {
     "kind": "ref",
     "from": "api",
     "to": "py_fn"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGatewayV2::Integration"
      ],
      "where": []
     },
     "to": "py_fn"
    }
   ]
  },
  {
   "id": "launcher_starts_state_machine",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a campaign launcher function",
   "checks": [
    {
     "kind": "ref",
     "from": "py_fn",
     "to": "sm"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "to": "sm"
    }
   ]
  },
  {
   "id": "cognito_client",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::Cognito::UserPoolClient"
    ],
    "where": []
   },
   "to": "pool",
   "tier": "core",
   "quote": "a Cognito user pool and application client that the template creates"
  },
  {
   "id": "api_cognito_protected",
   "kind": "any_of",
   "tier": "core",
   "quote": "protected by a Cognito user pool",
   "checks": [
    {
     "kind": "ref",
     "from": "api",
     "to": "pool"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGatewayV2::Authorizer"
      ],
      "where": []
     },
     "to": "pool"
    }
   ]
  },
  {
   "id": "delivery_callback_function",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a function that processes delivery status callbacks",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Events::Rule"
      ],
      "where": []
     },
     "to": "py_fn"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Lambda::EventSourceMapping",
       "AWS::SNS::Subscription",
       "AWS::SNS::Topic"
      ],
      "where": []
     },
     "to": "py_fn"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)callback|delivery[_ -]?status"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "optional_vector_collection",
   "kind": "exists",
   "tier": "core",
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
      "value": "AWS::OpenSearchServerless::Collection"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "Type"
      ],
      "op": "eq",
      "value": "VECTORSEARCH"
     }
    ]
   },
   "quote": "an optional semantic search capability backed by an OpenSearch Serverless vector collection",
   "justify": "\"vector collection\" is OpenSearch Serverless collection Type VECTORSEARCH"
  },
  {
   "id": "vector_collection_policies",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with its own encryption, network and data access policies that stays switched off by default",
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
        "op": "eq",
        "value": "AWS::OpenSearchServerless::SecurityPolicy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "Type"
        ],
        "op": "eq",
        "value": "encryption"
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
        "value": "AWS::OpenSearchServerless::SecurityPolicy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "Type"
        ],
        "op": "eq",
        "value": "network"
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
        "value": "AWS::OpenSearchServerless::AccessPolicy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "Type"
        ],
        "op": "eq",
        "value": "data"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "state_machine_log_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a log group for the state machine",
   "checks": [
    {
     "kind": "ref",
     "from": "sm",
     "to": "log_group"
    },
    {
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
        "value": "(?i)states|state.?machine|orchestrat"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "failed_executions_alarm",
   "kind": "all_of",
   "tier": "core",
   "quote": "a CloudWatch alarm that fires when state machine executions fail",
   "checks": [
    {
     "kind": "attr",
     "select": "alarm",
     "cond": {
      "path": [
       "Namespace"
      ],
      "op": "eq",
      "value": "AWS/States"
     }
    },
    {
     "kind": "ref",
     "from": "alarm",
     "to": "sm"
    }
   ]
  },
  {
   "id": "alarm_notifies_topic",
   "kind": "ref",
   "from": "alarm",
   "to": "topic",
   "tier": "detail",
   "quote": "an SNS topic and a CloudWatch alarm"
  },
  {
   "id": "sender_email_parameter",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "^[^@\\s]+@[^@\\s]+$"
   },
   "tier": "detail",
   "quote": "Sender identity values such as the notification email address and the messaging phone number identifiers should be parameters with safe placeholder defaults"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
