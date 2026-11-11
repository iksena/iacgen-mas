package intent.cfn.row_054

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fn": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "api": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "res": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": []
  },
  "meth": {
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
      "ANY"
     ]
    }
   ]
  },
  "hello_res": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "eq",
     "value": "hello"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "lambda",
   "kind": "exists",
   "tier": "core",
   "quote": "a simple \"Hello World\" Lambda function",
   "select": "fn"
  },
  {
   "id": "runtime",
   "kind": "attr",
   "tier": "core",
   "quote": "the Lambda function should use Python 3.12 runtime",
   "justify": "Python 3.12 is runtime python3.12",
   "select": "fn",
   "cond": {
    "path": [
     "Runtime"
    ],
    "op": "eq",
    "value": "python3.12"
   }
  },
  {
   "id": "handler",
   "kind": "attr",
   "tier": "core",
   "quote": "the handler named index.lambda_handler",
   "select": "fn",
   "cond": {
    "path": [
     "Handler"
    ],
    "op": "eq",
    "value": "index.lambda_handler"
   }
  },
  {
   "id": "returns_hello",
   "kind": "attr",
   "tier": "detail",
   "quote": "returns the text \"Hello, World\"",
   "select": "fn",
   "cond": {
    "path": [
     "Code",
     "ZipFile"
    ],
    "op": "regex",
    "value": "(?i)hello, world"
   }
  },
  {
   "id": "rest_api",
   "kind": "exists",
   "tier": "core",
   "quote": "an API Gateway REST API",
   "select": "api"
  },
  {
   "id": "hello_path",
   "kind": "any_of",
   "tier": "core",
   "quote": "when a GET request is made to the /hello path",
   "checks": [
    {
     "kind": "exists",
     "select": "hello_res"
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "contains",
      "value": "/hello"
     }
    }
   ]
  },
  {
   "id": "get_method",
   "kind": "any_of",
   "tier": "core",
   "quote": "when a GET request is made to the /hello path",
   "checks": [
    {
     "kind": "ref",
     "from": "meth",
     "to": "hello_res"
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?is)/hello\\W+(get|x-amazon-apigateway-any-method)\\b"
     }
    }
   ],
   "justify": "ANY also serves GET; an OpenAPI body nests the method under the path"
  },
  {
   "id": "method_to_lambda",
   "kind": "any_of",
   "tier": "core",
   "quote": "exposed through an API Gateway REST API",
   "checks": [
    {
     "kind": "ref",
     "from": "meth",
     "to": "fn"
    },
    {
     "kind": "attr",
     "select": "meth",
     "cond": {
      "path": [
       "Integration",
       "Uri"
      ],
      "op": "regex",
      "value": "(?i)lambda:path"
     }
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Body"
      ],
      "op": "regex",
      "value": "(?i)lambda:path"
     }
    }
   ],
   "justify": "a Lambda integration URI contains lambda:path"
  },
  {
   "id": "stage_prod",
   "kind": "any_of",
   "tier": "core",
   "quote": "the API should be deployed to a stage named \"prod\"",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Deployment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "StageName"
      ],
      "op": "eq",
      "value": "prod"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::ApiGateway::Stage"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "StageName"
      ],
      "op": "eq",
      "value": "prod"
     }
    }
   ]
  },
  {
   "id": "x_apigw_permission",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Lambda::Permission"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Principal"
    ],
    "op": "eq",
    "value": "apigateway.amazonaws.com"
   }
  },
  {
   "id": "x_role_basic_exec",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(logs:|AWSLambdaBasicExecutionRole)"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
