package intent.cfn.row_007

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pol": {
   "types": [
    "AWS::IoT::Policy"
   ],
   "where": []
  },
  "thing": {
   "types": [
    "AWS::IoT::Thing"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "iot_policy",
   "kind": "exists",
   "select": "pol",
   "tier": "core",
   "quote": "creates an AWS IoT policy"
  },
  {
   "id": "policy_name",
   "kind": "attr",
   "select": "pol",
   "cond": {
    "path": [
     "PolicyName"
    ],
    "op": "eq",
    "value": "FreeRTOSIoTPolicy"
   },
   "tier": "core",
   "quote": "the policy named \"FreeRTOSIoTPolicy\""
  },
  {
   "id": "policy_connect",
   "kind": "attr",
   "select": "pol",
   "tier": "core",
   "quote": "allowing Connect, Publish, Subscribe, and Receive actions",
   "justify": "iot:Connect is the IoT action named in the prompt",
   "cond": {
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
      "value": "iot:Connect"
     }
    ]
   }
  },
  {
   "id": "policy_publish",
   "kind": "attr",
   "select": "pol",
   "tier": "core",
   "quote": "allowing Connect, Publish, Subscribe, and Receive actions",
   "justify": "iot:Publish is the IoT action named in the prompt",
   "cond": {
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
      "value": "iot:Publish"
     }
    ]
   }
  },
  {
   "id": "policy_subscribe",
   "kind": "attr",
   "select": "pol",
   "tier": "core",
   "quote": "allowing Connect, Publish, Subscribe, and Receive actions",
   "justify": "iot:Subscribe is the IoT action named in the prompt",
   "cond": {
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
      "value": "iot:Subscribe"
     }
    ]
   }
  },
  {
   "id": "policy_receive",
   "kind": "attr",
   "select": "pol",
   "tier": "core",
   "quote": "allowing Connect, Publish, Subscribe, and Receive actions",
   "justify": "iot:Receive is the IoT action named in the prompt",
   "cond": {
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
      "value": "iot:Receive"
     }
    ]
   }
  },
  {
   "id": "policy_all_resources",
   "kind": "all_of",
   "tier": "core",
   "quote": "allowing Connect, Publish, Subscribe, and Receive actions for all resources",
   "justify": "'for all resources' means Resource * or an ARN wildcard covering every IoT resource",
   "checks": [
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
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
        "value": "iot:Connect"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:aws:iot:[^:]*:[^:]*:\\*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
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
        "value": "iot:Publish"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:aws:iot:[^:]*:[^:]*:\\*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
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
        "value": "iot:Subscribe"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:aws:iot:[^:]*:[^:]*:\\*)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pol",
     "cond": {
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
        "value": "iot:Receive"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "regex",
        "value": "^(\\*|arn:aws:iot:[^:]*:[^:]*:\\*)$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "iot_thing",
   "kind": "exists",
   "select": "thing",
   "tier": "core",
   "quote": "an IoT thing"
  },
  {
   "id": "thing_name",
   "kind": "attr",
   "select": "thing",
   "cond": {
    "path": [
     "ThingName"
    ],
    "op": "eq",
    "value": "MyFreeRTOSThing"
   },
   "tier": "core",
   "quote": "a thing named \"MyFreeRTOSThing\""
  },
  {
   "id": "thing_attribute",
   "kind": "attr",
   "select": "thing",
   "cond": {
    "path": [
     "AttributePayload",
     "Attributes"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "with a simple attribute key-value pair"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
