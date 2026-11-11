package intent.cfn.row_062

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "api": {
   "types": [
    "AWS::AppSync::GraphQLApi"
   ],
   "where": []
  },
  "schema": {
   "types": [
    "AWS::AppSync::GraphQLSchema"
   ],
   "where": []
  },
  "ds": {
   "types": [
    "AWS::AppSync::DataSource"
   ],
   "where": [
    {
     "path": [
      "Type"
     ],
     "op": "eq",
     "value": "AMAZON_EVENTBRIDGE"
    }
   ]
  },
  "bus": {
   "types": [
    "AWS::Events::EventBus"
   ],
   "where": []
  },
  "role": {
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
     "value": "appsync.amazonaws.com"
    }
   ]
  },
  "pol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "api",
   "kind": "exists",
   "select": "api",
   "tier": "core",
   "quote": "creates an AWS AppSync GraphQL API"
  },
  {
   "id": "api_iam_auth",
   "kind": "attr",
   "select": "api",
   "cond": {
    "path": [
     "AuthenticationType"
    ],
    "op": "eq",
    "value": "AWS_IAM"
   },
   "tier": "core",
   "quote": "with AWS IAM authentication",
   "justify": "\"AWS IAM authentication\" = AWS_IAM authentication type"
  },
  {
   "id": "schema_note_type",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Note\\b[^{]*\\{"
   },
   "tier": "core",
   "quote": "a Note type"
  },
  {
   "id": "schema_note_fields",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Note\\b[^{]*\\{[^}]*\\bNoteId\\b"
     }
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Note\\b[^{]*\\{[^}]*\\btitle\\b"
     }
    },
    {
     "kind": "attr",
     "select": "schema",
     "cond": {
      "path": [
       "Definition"
      ],
      "op": "regex",
      "value": "(?s)type\\s+Note\\b[^{]*\\{[^}]*\\bcontent\\b"
     }
    }
   ],
   "tier": "detail",
   "quote": "fields for NoteId, title, and content"
  },
  {
   "id": "schema_get_note",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Query\\b[^{]*\\{[^}]*\\bgetNote\\b"
   },
   "tier": "core",
   "quote": "a getNote query"
  },
  {
   "id": "schema_save_note",
   "kind": "attr",
   "select": "schema",
   "cond": {
    "path": [
     "Definition"
    ],
    "op": "regex",
    "value": "(?s)type\\s+Mutation\\b[^{]*\\{[^}]*\\bsaveNote\\b"
   },
   "tier": "core",
   "quote": "a saveNote mutation"
  },
  {
   "id": "eventbridge_datasource",
   "kind": "exists",
   "select": "ds",
   "tier": "core",
   "quote": "an Amazon EventBridge data source",
   "justify": "EventBridge data source = AMAZON_EVENTBRIDGE type"
  },
  {
   "id": "event_bus",
   "kind": "exists",
   "select": "bus",
   "tier": "core",
   "quote": "a custom EventBridge event bus"
  },
  {
   "id": "ds_targets_bus",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ds",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "ds",
     "cond": {
      "path": [
       "EventBridgeConfig",
       "EventBusArn"
      ],
      "op": "regex",
      "value": "event-bus/([^d]|d[^e]|de[^f])"
     }
    }
   ],
   "tier": "core",
   "quote": "configured to put events onto a custom EventBridge event bus",
   "justify": "a literal ARN naming any bus but default"
  },
  {
   "id": "appsync_role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "the necessary IAM role",
   "justify": "the role must be assumable by AppSync"
  },
  {
   "id": "role_put_events",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
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
        "value": "events:PutEvents"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
          "value": "events:PutEvents"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ],
   "tier": "core",
   "quote": "policy to allow AppSync to write events to that bus",
   "justify": "writing events = events:PutEvents"
  },
  {
   "id": "policy_targets_bus",
   "kind": "any_of",
   "tier": "detail",
   "quote": "write events to that bus",
   "justify": "the grant's resource is the bus, by reference or by a literal event-bus ARN",
   "checks": [
    {
     "kind": "ref",
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
          "value": "events:PutEvents"
         }
        ]
       }
      ]
     },
     "to": "bus"
    },
    {
     "kind": "ref",
     "from": {
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
          "value": "events:PutEvents"
         }
        ]
       }
      ]
     },
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "role",
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
        "value": "events:PutEvents"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "event-bus/[^*]"
       }
      ]
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
           "Resource",
           "*"
          ],
          "op": "regex",
          "value": "event-bus/[^*]"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ds_uses_role",
   "kind": "ref",
   "from": "ds",
   "to": "role",
   "tier": "detail",
   "quote": "the necessary IAM role and policy to allow AppSync to write events to that bus"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
