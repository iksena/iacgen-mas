package intent.cfn.row_258

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "lambdas": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": []
  },
  "py_lambdas": {
   "types": [
    "AWS::Lambda::Function"
   ],
   "where": [
    {
     "path": [
      "Runtime"
     ],
     "op": "regex",
     "value": "(?i)^python"
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
     "op": "eq",
     "value": "lambda.amazonaws.com"
    }
   ]
  },
  "apigw_role": {
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
     "value": "apigateway.amazonaws.com"
    }
   ]
  },
  "api": {
   "types": [
    "AWS::ApiGateway::RestApi"
   ],
   "where": []
  },
  "methods": {
   "types": [
    "AWS::ApiGateway::Method"
   ],
   "where": []
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
  "get_method": {
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
  },
  "shortid_resource": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "regex",
     "value": "^\\{[^}]+\\}$"
    }
   ]
  },
  "create_resource": {
   "types": [
    "AWS::ApiGateway::Resource"
   ],
   "where": [
    {
     "path": [
      "PathPart"
     ],
     "op": "regex",
     "value": "^[^{]"
    },
    {
     "path": [
      "PathPart"
     ],
     "op": "none_eq",
     "value": "admin"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "table",
   "tier": "core",
   "quote": "provision a DynamoDB table",
   "kind": "exists",
   "select": "table"
  },
  {
   "id": "table_name_default",
   "tier": "core",
   "quote": "named url-shortener-table by default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "TableName"
      ],
      "op": "eq",
      "value": "url-shortener-table"
     }
    }
   ]
  },
  {
   "id": "table_key_string",
   "tier": "core",
   "quote": "keyed on a short identifier string attribute",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "AttributeDefinitions",
     "*",
     "AttributeType"
    ],
    "op": "eq",
    "value": "S"
   },
   "justify": "string = S"
  },
  {
   "id": "table_hash_key",
   "tier": "detail",
   "quote": "keyed on a short identifier string attribute",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "KeySchema"
    ],
    "op": "len_eq",
    "value": 1
   },
   "justify": "keyed on one attribute = a single partition key, no sort key"
  },
  {
   "id": "table_provisioned",
   "tier": "detail",
   "quote": "modest provisioned capacity",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "BillingMode"
      ],
      "op": "eq",
      "value": "PROVISIONED"
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "ProvisionedThroughput",
       "ReadCapacityUnits"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "two_python_lambdas",
   "tier": "core",
   "quote": "two Python Lambda functions",
   "kind": "exists",
   "select": "py_lambdas",
   "min": 2
  },
  {
   "id": "single_lambda_role",
   "tier": "core",
   "quote": "that share a single execution role",
   "kind": "exists",
   "select": "lambda_role",
   "min": 1,
   "max": 1,
   "justify": "single role = exactly one"
  },
  {
   "id": "lambdas_use_role",
   "tier": "core",
   "quote": "share a single execution role",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "lambdas",
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "lambdas",
     "quantifier": "all",
     "cond": {
      "path": [
       "Role",
       "ref"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "create_id_length",
   "tier": "core",
   "quote": "generates a random short identifier of between twelve and sixteen characters",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "py_lambdas",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?s)(\\b12\\b.{0,600}\\b1[67]\\b|\\b1[67]\\b.{0,600}\\b12\\b)"
     }
    },
    {
     "kind": "attr",
     "select": "py_lambdas",
     "cond": {
      "path": [
       "Environment",
       "Variables"
      ],
      "op": "regex",
      "value": "(?s)(\\b12\\b.{0,300}\\b1[67]\\b|\\b1[67]\\b.{0,300}\\b12\\b)"
     }
    }
   ],
   "justify": "twelve and sixteen = 12 and 16 (17 as an exclusive upper bound)"
  },
  {
   "id": "create_stores_putitem",
   "tier": "detail",
   "quote": "stores it against the submitted long URL",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "dynamodb:PutItem"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "dynamodb:UpdateItem"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
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
        "value": "dynamodb:PutItem"
       }
      ]
     },
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDBFullAccess$"
     }
    }
   ],
   "justify": "storing an item = PutItem (or UpdateItem, which also creates it)"
  },
  {
   "id": "app_url_configurable",
   "tier": "detail",
   "quote": "built from a configurable application URL",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "py_lambdas",
     "cond": {
      "path": [
       "Environment",
       "Variables"
      ],
      "op": "regex",
      "value": "(?i)\"[a-z0-9_]*url[a-z0-9_]*\"\\s*:"
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
        "value": "(?i)url($|[^a-z]|prefix|base|param|value|root)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "retrieve_lookup",
   "tier": "detail",
   "quote": "looks an identifier up in the table",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "py_lambdas",
     "cond": {
      "path": [
       "Code",
       "ZipFile"
      ],
      "op": "regex",
      "value": "(?i)(get_item|getitem|\\.query\\()"
     }
    }
   ]
  },
  {
   "id": "retrieve_getitem_perm",
   "tier": "detail",
   "quote": "looks an identifier up in the table",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "dynamodb:GetItem"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "dynamodb:Query"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
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
        "value": "dynamodb:GetItem"
       }
      ]
     },
     "to": "lambda_role"
    },
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AmazonDynamoDBFullAccess$"
     }
    }
   ],
   "justify": "lookup = GetItem (or Query)"
  },
  {
   "id": "retrieve_redirect",
   "tier": "detail",
   "quote": "hands back the original URL as a redirect",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "py_lambdas",
     "cond": {
      "path": [
       "Code"
      ],
      "op": "regex",
      "value": "(?is)(\\b30[1278]\\b.{0,300}location|location.{0,300}\\b30[1278]\\b|HTTPStatus\\.(MOVED_PERMANENTLY|FOUND|SEE_OTHER|TEMPORARY_REDIRECT|PERMANENT_REDIRECT))"
     }
    },
    {
     "kind": "attr",
     "select": "get_method",
     "cond": {
      "path": [
       "Integration",
       "IntegrationResponses",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "StatusCode"
        ],
        "op": "regex",
        "value": "^30[1-8]$"
       },
       {
        "path": [
         "ResponseParameters"
        ],
        "op": "regex",
        "value": "(?i)location"
       }
      ]
     }
    }
   ],
   "justify": "a redirect is an HTTP 3xx with a Location header"
  },
  {
   "id": "rest_api",
   "tier": "core",
   "quote": "a regional REST API",
   "kind": "exists",
   "select": "api"
  },
  {
   "id": "api_regional",
   "tier": "core",
   "quote": "a regional REST API",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "EndpointConfiguration",
     "Types",
     "*"
    ],
    "op": "eq",
    "value": "REGIONAL"
   }
  },
  {
   "id": "resource_create",
   "tier": "core",
   "quote": "separate resources for creating a link",
   "kind": "ref",
   "from": "post_method",
   "to": "create_resource"
  },
  {
   "id": "resource_admin",
   "tier": "core",
   "quote": "for an admin path",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::ApiGateway::Resource"
    ],
    "where": [
     {
      "path": [
       "PathPart"
      ],
      "op": "regex",
      "value": "(?i)^admin$"
     }
    ]
   }
  },
  {
   "id": "resource_shortid",
   "tier": "core",
   "quote": "captures the identifier as a path parameter",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::ApiGateway::Resource"
    ],
    "where": [
     {
      "path": [
       "PathPart"
      ],
      "op": "regex",
      "value": "^\\{[^}]+\\}$"
     }
    ]
   },
   "justify": "a path parameter is written in braces"
  },
  {
   "id": "shortid_get_wired",
   "tier": "core",
   "quote": "the short link path that captures the identifier as a path parameter",
   "kind": "ref",
   "from": {
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
     },
     {
      "path": [
       "Integration",
       "Uri"
      ],
      "op": "regex",
      "value": "(?i):lambda:path/"
     }
    ]
   },
   "to": "shortid_resource"
  },
  {
   "id": "post_method_lambda",
   "tier": "core",
   "quote": "wiring the appropriate GET and POST methods to the matching functions",
   "kind": "ref",
   "from": "post_method",
   "to": "lambdas"
  },
  {
   "id": "get_method_lambda",
   "tier": "core",
   "quote": "wiring the appropriate GET and POST methods to the matching functions",
   "kind": "ref",
   "from": "get_method",
   "to": "lambdas"
  },
  {
   "id": "invoke_permissions",
   "tier": "core",
   "quote": "granting API Gateway permission to invoke them",
   "kind": "exists",
   "select": {
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
   "min": 2,
   "distinct_path": [
    "FunctionName"
   ],
   "justify": "two functions"
  },
  {
   "id": "deployed_test_stage",
   "tier": "core",
   "quote": "deploying the API to a test stage",
   "kind": "any_of",
   "checks": [
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
        "op": "eq",
        "value": "test"
       }
      ]
     }
    },
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
        "op": "eq",
        "value": "test"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "account_cloudwatch_role",
   "tier": "core",
   "quote": "configure the account level API Gateway role that permits CloudWatch logging",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::ApiGateway::Account"
    ],
    "where": []
   }
  },
  {
   "id": "account_role_ref",
   "tier": "core",
   "quote": "API Gateway role that permits CloudWatch logging",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::ApiGateway::Account"
    ],
    "where": []
   },
   "to": "apigw_role"
  },
  {
   "id": "account_role_logs",
   "tier": "detail",
   "quote": "role that permits CloudWatch logging",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGateway::Account"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
        "path": [
         "ManagedPolicyArns",
         "*"
        ],
        "op": "regex",
        "value": "AmazonAPIGatewayPushToCloudWatchLogs$"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::ApiGateway::Account"
      ],
      "where": []
     },
     "to": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": [
       {
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
      ]
     }
    }
   ]
  },
  {
   "id": "table_name_param",
   "tier": "detail",
   "quote": "expose the table name",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "url-shortener-table"
     }
    ]
   }
  },
  {
   "id": "function_prefix_param",
   "tier": "detail",
   "quote": "a function name prefix defaulting to url-shortener",
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
      "value": "(?i)(function|prefix)"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "url-shortener"
     }
    ]
   }
  },
  {
   "id": "functions_use_prefix",
   "tier": "detail",
   "quote": "a function name prefix defaulting to url-shortener",
   "kind": "attr",
   "select": "lambdas",
   "quantifier": "all",
   "cond": {
    "path": [
     "FunctionName"
    ],
    "op": "regex",
    "value": "^url-shortener"
   }
  },
  {
   "id": "runtime_param",
   "tier": "detail",
   "quote": "the Python runtime as parameters",
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
      "value": "(?i)runtime"
     },
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)^python"
     }
    ]
   }
  },
  {
   "id": "tag_env_param",
   "tier": "detail",
   "quote": "tagging inputs such as environment, service and owner",
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
      "value": "(?i)env"
     }
    ]
   }
  },
  {
   "id": "tag_service_param",
   "tier": "detail",
   "quote": "tagging inputs such as environment, service and owner",
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
      "value": "(?i)service"
     }
    ]
   }
  },
  {
   "id": "tags_applied",
   "tier": "detail",
   "quote": "tagging inputs such as environment, service and owner",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "lambdas",
     "cond": {
      "path": [
       "Tags",
       "*",
       "Key"
      ],
      "op": "regex",
      "value": "(?i)(env|service|owner)"
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "Tags",
       "*",
       "Key"
      ],
      "op": "regex",
      "value": "(?i)(env|service|owner)"
     }
    },
    {
     "kind": "attr",
     "select": "api",
     "cond": {
      "path": [
       "Tags",
       "*",
       "Key"
      ],
      "op": "regex",
      "value": "(?i)(env|service|owner)"
     }
    }
   ]
  },
  {
   "id": "x_basic_exec",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "AWSLambdaBasicExecutionRole"
     }
    },
    {
     "kind": "attr",
     "select": "lambda_role",
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
    }
   ]
  },
  {
   "id": "x_updateitem",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "lambda_role",
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
      "value": "dynamodb:UpdateItem"
     }
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
        "value": "dynamodb:UpdateItem"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
