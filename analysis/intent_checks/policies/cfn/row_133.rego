package intent.cfn.row_133

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
  "apis": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "apigw_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "apigateway.amazonaws.com"
    }
   ]
  },
  "sm_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "states.amazonaws.com"
    }
   ]
  },
  "deploys": {
   "types": [
    "AWS::ApiGateway::Deployment"
   ],
   "where": []
  },
  "stages": {
   "types": [
    "AWS::ApiGateway::Stage"
   ],
   "where": []
  },
  "pol_start": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": [
    {
     "path": [
      "PolicyDocument",
      "Statement",
      "*",
      "Action",
      "*"
     ],
     "op": "glob_covers",
     "value": "states:StartExecution"
    }
   ]
  },
  "post_m": {
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
  "get_m": {
   "types": [
    "AWS::ApiGateway::Method"
   ],
   "where": [
    {
     "path": [
      "HttpMethod"
     ],
     "op": "eq",
     "value": "GET"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "sm_exists",
   "kind": "exists",
   "select": "sm",
   "tier": "core",
   "quote": "creates a Step Functions state machine"
  },
  {
   "id": "sm_two_pass_states",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sm",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?is)Type\"?\\s*:\\s*\"?Pass\\b.*Type\"?\\s*:\\s*\"?Pass\\b"
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
      "value": "(?is)Type\"?\\s*:\\s*\"?Pass\\b.*Type\"?\\s*:\\s*\"?Pass\\b"
     }
    }
   ],
   "tier": "core",
   "quote": "a simple two-step pass workflow",
   "justify": "two-step pass workflow implies two Pass states"
  },
  {
   "id": "two_rest_apis",
   "kind": "exists",
   "select": "apis",
   "min": 2,
   "tier": "core",
   "quote": "provisions two separate API Gateway REST APIs"
  },
  {
   "id": "get_endpoint",
   "tier": "core",
   "quote": "one exposing a GET endpoint",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::RestApi"
      ],
      "where": [
       {
        "path": [
         "Body",
         "paths",
         "*",
         "get"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "get_m",
     "to": "apis"
    }
   ]
  },
  {
   "id": "post_endpoint",
   "tier": "core",
   "quote": "the other a POST endpoint",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::RestApi"
      ],
      "where": [
       {
        "path": [
         "Body",
         "paths",
         "*",
         "post"
        ],
        "op": "present"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "post_m",
     "to": "apis"
    }
   ]
  },
  {
   "id": "get_post_separate_apis",
   "kind": "any_of",
   "tier": "core",
   "quote": "one exposing a GET endpoint and the other a POST endpoint",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::RestApi"
      ],
      "where": [
       {
        "path": [
         "Body",
         "paths",
         "*",
         "get"
        ],
        "op": "present"
       },
       {
        "path": [
         "Body",
         "paths",
         "*",
         "post"
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
       "AWS::ApiGateway::RestApi"
      ],
      "where": [
       {
        "path": [
         "Body",
         "paths",
         "*",
         "post"
        ],
        "op": "present"
       },
       {
        "path": [
         "Body",
         "paths",
         "*",
         "get"
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
       "AWS::ApiGateway::Method"
      ],
      "where": [
       {
        "path": [
         "HttpMethod"
        ],
        "op": "in",
        "value": [
         "GET",
         "POST"
        ]
       }
      ]
     },
     "distinct_path": [
      "RestApiId"
     ],
     "min": 2
    }
   ]
  },
  {
   "id": "two_apigw_roles",
   "kind": "exists",
   "select": "apigw_role",
   "min": 2,
   "tier": "core",
   "quote": "each with its own IAM role allowing API Gateway to start state machine executions",
   "justify": "each of two APIs has its own role"
  },
  {
   "id": "roles_allow_start_execution",
   "tier": "core",
   "quote": "IAM role allowing API Gateway to start state machine executions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "apigw_role",
     "quantifier": "all",
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
        "value": "states:StartExecution"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "apigw_role",
     "quantifier": "all",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)AWSStepFunctionsFullAccess"
     }
    },
    {
     "kind": "exists",
     "select": "pol_start",
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "states:StartExecution"
       },
       {
        "path": [
         "Roles"
        ],
        "op": "len_gte",
        "value": 2
       }
      ]
     }
    }
   ],
   "justify": "each of the two roles has the grant"
  },
  {
   "id": "deploy_each_api",
   "tier": "core",
   "quote": "deploys each API to a specific stage",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "deploys",
     "distinct_path": [
      "RestApiId"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": "stages",
     "distinct_path": [
      "RestApiId"
     ],
     "min": 2
    }
   ],
   "justify": "each of the two APIs has its own deployment or stage"
  },
  {
   "id": "deployments_named_stage",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::Stage"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "present"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": [
       {
        "path": [
         "StageName"
        ],
        "op": "present"
       }
      ]
     },
     "min": 2
    }
   ],
   "tier": "detail",
   "quote": "deploys each API to a specific stage"
  },
  {
   "id": "apis_use_roles",
   "tier": "detail",
   "quote": "each with its own IAM role allowing API Gateway to start state machine executions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ApiGateway::Method"
      ],
      "where": []
     },
     "distinct_path": [
      "Integration",
      "Credentials"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": "apis",
     "distinct_path": [
      "Body",
      "paths",
      "*",
      "*",
      "x-amazon-apigateway-integration",
      "credentials"
     ],
     "min": 2
    }
   ],
   "justify": "each API uses its own role, so two different integration credentials"
  },
  {
   "id": "integration_start_execution",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "apis",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?i)StartExecution"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Method"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Integration"
      ],
      "op": "regex",
      "value": "(?i)StartExecution"
     }
    }
   ],
   "tier": "detail",
   "quote": "allowing API Gateway to start state machine executions"
  },
  {
   "id": "sm_has_role",
   "kind": "ref",
   "from": "sm",
   "to": "sm_role",
   "tier": "detail",
   "quote": "ensuring all required IAM roles and resources are fully created within the stack"
  },
  {
   "id": "x_apigw_role_scoped_to_sm",
   "kind": "ref",
   "from": "apigw_role",
   "to": "sm",
   "tier": "extra"
  },
  {
   "id": "x_integration_post",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "apis",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?i)(httpMethod:POST|\"httpMethod\"\\s*:\\s*\"POST\")"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Method"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Integration",
       "HttpMethod"
      ],
      "op": "eq",
      "value": "POST"
     }
    }
   ],
   "tier": "extra"
  },
  {
   "id": "x_deployments_bind_apis",
   "kind": "ref",
   "from": "deploys",
   "to": "apis",
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
