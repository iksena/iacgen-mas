package intent.tf.row_028

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "api",
   "tier": "core",
   "quote": "creates an Amazon API Gateway REST API named \"HelloWorldAPI\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_api_gateway_rest_api"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "HelloWorldAPI"
     }
    ]
   }
  },
  {
   "id": "api_desc",
   "tier": "detail",
   "quote": "the description \"API Gateway for Hello World Lambda\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_api_gateway_rest_api"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "description"
    ],
    "op": "eq",
    "value": "API Gateway for Hello World Lambda"
   }
  },
  {
   "id": "resource",
   "tier": "core",
   "quote": "a sub-resource path \"hello\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_api_gateway_resource"
    ],
    "where": [
     {
      "path": [
       "path_part"
      ],
      "op": "eq",
      "value": "hello"
     }
    ]
   }
  },
  {
   "id": "resource_in_api",
   "tier": "core",
   "quote": "a sub-resource path \"hello\"",
   "kind": "ref",
   "from": {
    "types": [
     "aws_api_gateway_resource"
    ],
    "where": [
     {
      "path": [
       "path_part"
      ],
      "op": "eq",
      "value": "hello"
     }
    ]
   },
   "to": {
    "types": [
     "aws_api_gateway_rest_api"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "HelloWorldAPI"
     }
    ]
   }
  },
  {
   "id": "resource_on_root",
   "tier": "core",
   "quote": "directly off the root resource",
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
      "value": "aws_api_gateway_resource"
     },
     {
      "path": [
       "properties",
       "path_part"
      ],
      "op": "eq",
      "value": "hello"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "parent_id"
    ],
    "op": "contains",
    "value": "root_resource_id"
   }
  },
  {
   "id": "method_any",
   "tier": "core",
   "quote": "configured with an \"ANY\" HTTP method",
   "kind": "exists",
   "select": {
    "types": [
     "aws_api_gateway_method"
    ],
    "where": [
     {
      "path": [
       "http_method"
      ],
      "op": "eq",
      "value": "ANY"
     }
    ]
   }
  },
  {
   "id": "method_on_resource",
   "tier": "core",
   "quote": "configured with an \"ANY\" HTTP method",
   "kind": "ref",
   "from": {
    "types": [
     "aws_api_gateway_method"
    ],
    "where": [
     {
      "path": [
       "http_method"
      ],
      "op": "eq",
      "value": "ANY"
     }
    ]
   },
   "to": {
    "types": [
     "aws_api_gateway_resource"
    ],
    "where": [
     {
      "path": [
       "path_part"
      ],
      "op": "eq",
      "value": "hello"
     }
    ]
   }
  },
  {
   "id": "method_no_auth",
   "tier": "core",
   "quote": "configured with an \"ANY\" HTTP method that requires no authorization",
   "kind": "ref",
   "justify": "requires no authorization means authorization NONE",
   "from": {
    "types": [
     "aws_api_gateway_method"
    ],
    "where": [
     {
      "path": [
       "http_method"
      ],
      "op": "eq",
      "value": "ANY"
     },
     {
      "path": [
       "authorization"
      ],
      "op": "eq",
      "value": "NONE"
     }
    ]
   },
   "to": {
    "types": [
     "aws_api_gateway_resource"
    ],
    "where": [
     {
      "path": [
       "path_part"
      ],
      "op": "eq",
      "value": "hello"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
