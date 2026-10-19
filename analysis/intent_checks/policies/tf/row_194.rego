package intent.tf.row_194

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "http_api": {
   "types": [
    "aws_apigatewayv2_api"
   ],
   "where": [
    {
     "path": [
      "protocol_type"
     ],
     "op": "eq",
     "value": "HTTP"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "default_http_api",
   "kind": "exists",
   "tier": "core",
   "quote": "The API type must be determined by a variable defaulting to \"http\"",
   "select": "http_api"
  },
  {
   "id": "api_name_default",
   "kind": "attr",
   "tier": "core",
   "quote": "using a default API name of \"benchmark-api\"",
   "select": "http_api",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "benchmark-api"
   }
  },
  {
   "id": "api_type_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "determined by a variable defaulting to \"http\"",
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
      "value": "http"
     }
    ]
   }
  },
  {
   "id": "http_stage_auto_deploy",
   "kind": "ref",
   "tier": "core",
   "quote": "auto-deployed stages",
   "to": "http_api",
   "from": {
    "types": [
     "aws_apigatewayv2_stage"
    ],
    "where": [
     {
      "path": [
       "auto_deploy"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "stage_name_suffix",
   "kind": "attr",
   "tier": "detail",
   "quote": "deploying stages named using the environment name value followed by the suffix \"-stage\"",
   "select": {
    "types": [
     "aws_apigatewayv2_stage"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "-stage$"
   }
  },
  {
   "id": "rest_api_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "or a REST API (v1)",
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
      "value": "aws_api_gateway_rest_api"
     }
    ]
   }
  },
  {
   "id": "http_routes",
   "kind": "all_of",
   "tier": "detail",
   "quote": "For HTTP APIs, the template should support dynamic route mappings",
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
        "value": "aws_apigatewayv2_route"
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
        "value": "aws_apigatewayv2_integration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "http_custom_domain_tls12",
   "kind": "all_of",
   "tier": "detail",
   "quote": "custom domain configurations with TLS 1.2 regional ACM certificates",
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
        "value": "aws_apigatewayv2_domain_name"
       },
       {
        "path": [
         "properties",
         "domain_name_configuration"
        ],
        "op": "contains",
        "value": "TLS_1_2"
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
        "value": "aws_apigatewayv2_domain_name"
       },
       {
        "path": [
         "properties",
         "domain_name_configuration"
        ],
        "op": "contains",
        "value": "REGIONAL"
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
        "value": "aws_apigatewayv2_api_mapping"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "route53_alias_a",
   "kind": "exists",
   "tier": "detail",
   "quote": "optional Route 53 alias A records",
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
      "value": "aws_route53_record"
     },
     {
      "path": [
       "properties",
       "type"
      ],
      "op": "contains",
      "value": "A"
     },
     {
      "path": [
       "properties",
       "alias"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "http_vpc_link",
   "kind": "exists",
   "tier": "detail",
   "quote": "HTTP VPC links created across private subnets",
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
      "value": "aws_apigatewayv2_vpc_link"
     }
    ]
   }
  },
  {
   "id": "rest_resources_methods",
   "kind": "all_of",
   "tier": "detail",
   "quote": "For REST APIs, the module must support dynamic resource path mapping, route methods with path parameter overrides",
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
        "value": "aws_api_gateway_resource"
       },
       {
        "path": [
         "properties",
         "path_part"
        ],
        "op": "present",
        "value": ""
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
        "value": "aws_api_gateway_method"
       },
       {
        "path": [
         "properties",
         "request_parameters"
        ],
        "op": "present"
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
        "value": "aws_api_gateway_integration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rest_ip_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "optional IP source restriction resource policies",
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
        "value": "aws_api_gateway_rest_api_policy"
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
        "value": "aws_api_gateway_rest_api"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rest_redeploy_triggers",
   "kind": "exists",
   "tier": "detail",
   "quote": "automatic redeployment triggers",
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
      "value": "aws_api_gateway_deployment"
     },
     {
      "path": [
       "properties",
       "triggers"
      ],
      "op": "present",
      "value": ""
     }
    ]
   }
  },
  {
   "id": "usage_plan_api_key",
   "kind": "all_of",
   "tier": "detail",
   "quote": "usage plans with API keys",
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
        "value": "aws_api_gateway_usage_plan"
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
        "value": "aws_api_gateway_api_key"
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
        "value": "aws_api_gateway_usage_plan_key"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "api_key_ssm_securestring",
   "kind": "exists",
   "tier": "core",
   "quote": "saved as SecureString parameters in SSM Parameter Store",
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
      "value": "aws_ssm_parameter"
     },
     {
      "path": [
       "properties",
       "type"
      ],
      "op": "contains",
      "value": "SecureString"
     }
    ]
   }
  },
  {
   "id": "authorizer_lambda_node16",
   "kind": "all_of",
   "tier": "core",
   "quote": "custom Lambda authorizers featuring Node.js 16.x functions",
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
        "value": "aws_api_gateway_authorizer"
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
        "value": "aws_lambda_function"
       },
       {
        "path": [
         "properties",
         "runtime"
        ],
        "op": "regex",
        "value": "(?i)nodejs"
       }
      ]
     }
    }
   ],
   "justify": "nodejs16.x is deprecated and can no longer be used to create functions; any Node.js runtime meets the intent"
  },
  {
   "id": "authorizer_roles_policies",
   "kind": "exists",
   "tier": "detail",
   "quote": "invocation roles, and execution policies",
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
       "aws_iam_role_policy_attachment"
      ]
     }
    ]
   }
  },
  {
   "id": "rest_vpc_link_nlb",
   "kind": "exists",
   "tier": "core",
   "quote": "automatically provision an internal Network Load Balancer across private subnets",
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
      "value": "aws_lb"
     },
     {
      "path": [
       "properties",
       "load_balancer_type"
      ],
      "op": "contains",
      "value": "network"
     },
     {
      "path": [
       "properties",
       "internal"
      ],
      "op": "contains",
      "value": "true"
     }
    ]
   },
   "justify": "prompt says \"internal\" Network Load Balancer"
  },
  {
   "id": "nlb_target_group",
   "kind": "exists",
   "tier": "core",
   "quote": "a target group targeting an ALB ID at a configurable TCP port (defaulting to 443)",
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
      "value": "aws_lb_target_group"
     },
     {
      "path": [
       "properties",
       "protocol"
      ],
      "op": "contains",
      "value": "TCP"
     },
     {
      "path": [
       "properties",
       "port"
      ],
      "op": "contains",
      "value": "443"
     }
    ]
   },
   "justify": "TCP port defaulting to 443 is stated"
  },
  {
   "id": "nlb_target_group_alb_https_hc",
   "kind": "exists",
   "tier": "detail",
   "quote": "targeting an ALB ID at a configurable TCP port (defaulting to 443) with HTTPS health checks",
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
      "value": "aws_lb_target_group"
     },
     {
      "path": [
       "properties",
       "target_type"
      ],
      "op": "contains",
      "value": "alb"
     },
     {
      "path": [
       "properties",
       "health_check"
      ],
      "op": "contains",
      "value": "HTTPS"
     }
    ]
   }
  },
  {
   "id": "tg_attachment_listener",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a target group attachment, a TCP listener",
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
        "value": "aws_lb_target_group_attachment"
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
        "value": "aws_lb_listener"
       },
       {
        "path": [
         "properties",
         "protocol"
        ],
        "op": "contains",
        "value": "TCP"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rest_vpc_link_to_nlb",
   "kind": "exists",
   "tier": "core",
   "quote": "an API Gateway VPC link targeting the load balancer ARN",
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
      "value": "aws_api_gateway_vpc_link"
     },
     {
      "path": [
       "properties",
       "target_arns"
      ],
      "op": "contains",
      "value": "aws_lb."
     }
    ]
   }
  },
  {
   "id": "authorizer_invocation_grant",
   "kind": "any_of",
   "tier": "detail",
   "quote": "invocation roles, and execution policies",
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "apigateway.amazonaws.com"
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
        "value": "aws_lambda_permission"
       },
       {
        "path": [
         "properties",
         "principal"
        ],
        "op": "contains",
        "value": "apigateway.amazonaws.com"
       }
      ]
     }
    }
   ],
   "justify": "an API Gateway invocation role or an equivalent lambda permission for apigateway.amazonaws.com"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
