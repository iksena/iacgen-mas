# GENERATED from specs/cfn/row_081.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_081

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::ApiGatewayV2::Api"
   ],
   "where": [
    {
     "path": [
      "ProtocolType"
     ],
     "op": "eq",
     "value": "WEBSOCKET"
    }
   ]
  },
  "route_default": {
   "types": [
    "AWS::ApiGatewayV2::Route"
   ],
   "where": [
    {
     "path": [
      "RouteKey"
     ],
     "op": "eq",
     "value": "$default"
    }
   ]
  },
  "integ": {
   "types": [
    "AWS::ApiGatewayV2::Integration"
   ],
   "where": []
  },
  "sfn": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "websocket_api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "a serverless WebSocket API using API Gateway"
  },
  {
   "id": "state_machine",
   "kind": "exists",
   "select": "sfn",
   "tier": "core",
   "quote": "a standard Step Functions state machine"
  },
  {
   "id": "state_machine_standard",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a standard Step Functions state machine",
   "checks": [
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "StateMachineType"
      ],
      "op": "eq",
      "value": "STANDARD"
     }
    },
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "StateMachineType"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "default_route",
   "kind": "ref",
   "from": "route_default",
   "to": "api",
   "tier": "core",
   "quote": "the default route on the WebSocket API"
  },
  {
   "id": "default_route_integration",
   "kind": "ref",
   "from": "route_default",
   "to": "integ",
   "tier": "core",
   "quote": "the default route on the WebSocket API triggers a new execution of the state machine"
  },
  {
   "id": "integration_start_execution",
   "kind": "attr",
   "select": "integ",
   "cond": {
    "path": [
     "IntegrationUri"
    ],
    "op": "regex",
    "value": "(?i)states:action/StartExecution"
   },
   "tier": "core",
   "quote": "asynchronously invokes a standard Step Functions state machine"
  },
  {
   "id": "integration_targets_state_machine",
   "kind": "ref",
   "from": "integ",
   "to": "sfn",
   "tier": "detail",
   "quote": "triggers a new execution of the state machine"
  },
  {
   "id": "integration_passes_connection_id",
   "kind": "attr",
   "select": "integ",
   "cond": {
    "path": [
     "RequestTemplates"
    ],
    "op": "regex",
    "value": "(?i)context\\.connectionId"
   },
   "tier": "detail",
   "quote": "passing the incoming message along with the connection ID as input"
  },
  {
   "id": "sfn_wait_five_seconds",
   "kind": "any_of",
   "tier": "core",
   "quote": "after a five-second wait",
   "checks": [
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "\"Seconds\"\\s*:\\s*5\\b"
     }
    },
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "Definition",
       "States",
       "*",
       "Seconds"
      ],
      "op": "eq",
      "value": 5
     }
    }
   ],
   "justify": "\"five-second wait\" = Wait state with Seconds 5"
  },
  {
   "id": "sfn_post_to_connection",
   "kind": "any_of",
   "tier": "core",
   "quote": "the state machine sends a response back to the connected WebSocket client using the API Gateway Management API",
   "checks": [
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "DefinitionString"
      ],
      "op": "regex",
      "value": "(?i)(@connections|apigatewaymanagementapi|posttoconnection)"
     }
    },
    {
     "kind": "attr",
     "select": "sfn",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?i)(@connections|apigatewaymanagementapi|posttoconnection)"
     }
    },
    {
     "kind": "ref",
     "from": "sfn",
     "to": {
      "types": [
       "AWS::Lambda::Function"
      ],
      "where": [
       {
        "path": [
         "Code"
        ],
        "op": "regex",
        "value": "(?i)(post_?to_?connection|apigatewaymanagementapi|@connections)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sfn_role_manage_connections",
   "kind": "any_of",
   "tier": "detail",
   "quote": "using the API Gateway Management API",
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
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "execute-api:ManageConnections"
     }
    },
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
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "execute-api:ManageConnections"
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
       "PolicyDocument",
       "Statement",
       "*",
       "Action"
      ],
      "op": "glob_covers",
      "value": "execute-api:ManageConnections"
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
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "execute-api:ManageConnections"
     }
    }
   ]
  },
  {
   "id": "stage_name_parameter",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "api"
   },
   "tier": "detail",
   "quote": "an API stage name parameter defaulting to \"api\""
  },
  {
   "id": "stage_api",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::ApiGatewayV2::Stage"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "StageName"
    ],
    "op": "eq",
    "value": "api"
   },
   "tier": "detail",
   "quote": "an API stage name parameter defaulting to \"api\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
