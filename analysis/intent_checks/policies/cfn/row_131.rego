package intent.cfn.row_131

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "gw_role": {
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
     "value": "bedrock-agentcore.amazonaws.com"
    }
   ]
  },
  "gw": {
   "types": [
    "AWS::BedrockAgentCore::Gateway"
   ],
   "where": []
  },
  "target": {
   "types": [
    "AWS::BedrockAgentCore::GatewayTarget"
   ],
   "where": []
  },
  "ssm_param": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": []
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
   "id": "gateway_role_trust",
   "kind": "exists",
   "select": "gw_role",
   "tier": "core",
   "quote": "Create an IAM role for the 'bedrock-agentcore.amazonaws.com' service"
  },
  {
   "id": "gateway_role_invoke_lambda",
   "kind": "any_of",
   "tier": "core",
   "quote": "grants permission to invoke a Lambda function",
   "checks": [
    {
     "kind": "attr",
     "select": "gw_role",
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
      "value": "lambda:InvokeFunction"
     }
    },
    {
     "kind": "ref",
     "to": "gw_role",
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
        "value": "lambda:InvokeFunction"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "role_arn_in_ssm_parameter",
   "kind": "ref",
   "from": "ssm_param",
   "to": "gw_role",
   "tier": "core",
   "quote": "store this new IAM role's ARN in a standard SSM parameter"
  },
  {
   "id": "role_arn_parameter_standard",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a standard SSM parameter",
   "justify": "\"standard\" = the Standard tier (the default when Tier is omitted)",
   "checks": [
    {
     "kind": "ref",
     "to": "gw_role",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Tier"
        ],
        "op": "eq",
        "value": "Standard"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "gw_role",
     "from": {
      "types": [
       "AWS::SSM::Parameter"
      ],
      "where": [
       {
        "path": [
         "Tier"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "gateway_exists",
   "kind": "exists",
   "select": "gw",
   "tier": "core",
   "quote": "Provision the AgentCore Gateway"
  },
  {
   "id": "gateway_mcp_protocol",
   "kind": "attr",
   "select": "gw",
   "cond": {
    "path": [
     "ProtocolType"
    ],
    "op": "eq",
    "value": "MCP"
   },
   "tier": "core",
   "quote": "AgentCore Gateway infrastructure for MCP (Model Context Protocol) integration"
  },
  {
   "id": "gateway_custom_jwt",
   "kind": "attr",
   "select": "gw",
   "cond": {
    "path": [
     "AuthorizerType"
    ],
    "op": "eq",
    "value": "CUSTOM_JWT"
   },
   "tier": "core",
   "quote": "configured with a custom JWT authorizer"
  },
  {
   "id": "jwt_discovery_url_and_client",
   "kind": "all_of",
   "tier": "detail",
   "quote": "references a Cognito discovery URL and client ID",
   "checks": [
    {
     "kind": "attr",
     "select": "gw",
     "cond": {
      "path": [
       "AuthorizerConfiguration",
       "CustomJWTAuthorizer",
       "DiscoveryUrl"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "gw",
     "cond": {
      "path": [
       "AuthorizerConfiguration",
       "CustomJWTAuthorizer"
      ],
      "op": "regex",
      "value": "(?i)Allowed(Clients|Audience)"
     }
    }
   ]
  },
  {
   "id": "gateway_uses_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Create an IAM role for the 'bedrock-agentcore.amazonaws.com' service",
   "checks": [
    {
     "kind": "ref",
     "from": "gw",
     "to": "gw_role"
    },
    {
     "kind": "ref",
     "from": "gw",
     "to": "ssm_param"
    }
   ]
  },
  {
   "id": "target_on_gateway",
   "kind": "ref",
   "from": "target",
   "to": "gw",
   "tier": "core",
   "quote": "create a gateway target connecting the gateway to the Lambda function"
  },
  {
   "id": "target_lambda",
   "kind": "attr",
   "select": "target",
   "cond": {
    "path": [
     "TargetConfiguration",
     "Mcp",
     "Lambda",
     "LambdaArn"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "connecting the gateway to the Lambda function"
  },
  {
   "id": "tool_schema_operations",
   "kind": "all_of",
   "tier": "core",
   "quote": "an MCP inline tool schema with 'invoke_endpoint' and 'get_results' operations",
   "checks": [
    {
     "kind": "attr",
     "select": "target",
     "cond": {
      "path": [
       "TargetConfiguration",
       "Mcp",
       "Lambda",
       "ToolSchema",
       "InlinePayload"
      ],
      "op": "contains",
      "value": "invoke_endpoint"
     }
    },
    {
     "kind": "attr",
     "select": "target",
     "cond": {
      "path": [
       "TargetConfiguration",
       "Mcp",
       "Lambda",
       "ToolSchema",
       "InlinePayload"
      ],
      "op": "contains",
      "value": "get_results"
     }
    }
   ]
  },
  {
   "id": "param_project_name_default",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "protein-engineering"
   },
   "tier": "detail",
   "quote": "parameters for the project name (defaulting to 'protein-engineering')"
  },
  {
   "id": "param_gateway_description",
   "kind": "attr",
   "select": "param",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)desc"
   },
   "tier": "detail",
   "quote": "gateway description"
  },
  {
   "id": "param_optional_gateway_name",
   "kind": "attr",
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
      "value": "(?i)gateway.?name"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": ""
   },
   "tier": "detail",
   "quote": "an optional gateway name that auto-generates from the project name if left blank",
   "justify": "\"optional ... if left blank\" implies a blank default"
  },
  {
   "id": "gateway_name_from_project",
   "kind": "attr",
   "select": "gw",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "regex",
    "value": "(?i)protein.?engineering"
   },
   "tier": "detail",
   "quote": "auto-generates from the project name if left blank",
   "justify": "with the gateway-name parameter blank, the name derives from the project-name default 'protein-engineering'"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
