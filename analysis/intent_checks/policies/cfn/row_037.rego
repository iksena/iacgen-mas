package intent.cfn.row_037

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bus": {
   "types": [
    "AWS::Events::EventBus"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "rule_off": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "State"
     ],
     "op": "eq",
     "value": "DISABLED"
    }
   ]
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "arch": {
   "types": [
    "AWS::Events::Archive"
   ],
   "where": []
  },
  "disc": {
   "types": [
    "AWS::EventSchemas::Discoverer"
   ],
   "where": []
  },
  "ssm": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "RetailDemoStore-eventbus"
    }
   ]
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "out_exp": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "export"
     ],
     "op": "eq",
     "value": "retaildemostore-bus"
    }
   ]
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "ssm_name": {
   "types": [
    "AWS::SSM::Parameter"
   ],
   "where": [
    {
     "path": [
      "Name"
     ],
     "op": "eq",
     "value": "RetailDemoStore-eventbus"
    },
    {
     "path": [
      "Value",
      "attr"
     ],
     "op": "none_eq",
     "value": "Arn"
    }
   ]
  },
  "out_exp_name": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "export"
     ],
     "op": "eq",
     "value": "retaildemostore-bus"
    },
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "Arn"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "bus",
   "tier": "core",
   "quote": "an EventBridge custom event bus with the name \"retaildemostore-bus\"",
   "kind": "attr",
   "select": "bus",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "retaildemostore-bus"
   }
  },
  {
   "id": "rule_disabled",
   "tier": "core",
   "quote": "a disabled catch-all rule",
   "kind": "exists",
   "select": "rule_off"
  },
  {
   "id": "rule_catch_all",
   "tier": "core",
   "quote": "a disabled catch-all rule that sends all events",
   "kind": "attr",
   "select": "rule_off",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "(?i)(\"\\*\"|prefix\":\\s*\"\"|exists\":\\s*true|\"account\"|^\\{\\}$)"
   },
   "justify": "catch-all: the pattern matches every event (wildcard, empty prefix, exists, or the account), not a named source"
  },
  {
   "id": "rule_on_bus",
   "tier": "detail",
   "quote": "a disabled catch-all rule that sends all events",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rule_off",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "rule_off",
     "cond": {
      "path": [
       "EventBusName"
      ],
      "op": "eq",
      "value": "retaildemostore-bus"
     }
    }
   ],
   "justify": "the catch-all rule belongs to the custom bus the prompt describes"
  },
  {
   "id": "rule_to_log",
   "tier": "core",
   "quote": "sends all events to a CloudWatch log group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rule_off",
     "to": "lg"
    },
    {
     "kind": "attr",
     "select": "rule_off",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Arn"
      ],
      "op": "regex",
      "value": "(?i):log-group:"
     }
    }
   ]
  },
  {
   "id": "log_group",
   "tier": "core",
   "quote": "a CloudWatch log group with 120-day retention",
   "kind": "exists",
   "select": "lg"
  },
  {
   "id": "log_retention",
   "tier": "core",
   "quote": "a CloudWatch log group with 120-day retention",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 120
   }
  },
  {
   "id": "archive",
   "tier": "core",
   "quote": "an event archive with 120-day retention",
   "kind": "exists",
   "select": "arch"
  },
  {
   "id": "archive_retention",
   "tier": "core",
   "quote": "an event archive with 120-day retention",
   "kind": "attr",
   "select": "arch",
   "cond": {
    "path": [
     "RetentionDays"
    ],
    "op": "eq",
    "value": 120
   }
  },
  {
   "id": "archive_bus",
   "tier": "detail",
   "quote": "an event archive",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "arch",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "arch",
     "cond": {
      "path": [
       "SourceArn"
      ],
      "op": "contains",
      "value": "retaildemostore-bus"
     }
    }
   ],
   "justify": "an archive of the retail demo store bus"
  },
  {
   "id": "discoverer",
   "tier": "core",
   "quote": "an EventBridge schema discoverer",
   "kind": "exists",
   "select": "disc"
  },
  {
   "id": "discoverer_bus",
   "tier": "detail",
   "quote": "an EventBridge schema discoverer",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "disc",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "disc",
     "cond": {
      "path": [
       "SourceArn"
      ],
      "op": "contains",
      "value": "retaildemostore-bus"
     }
    }
   ],
   "justify": "discoverer of the retail demo store bus"
  },
  {
   "id": "ssm",
   "tier": "core",
   "quote": "an SSM parameter named \"RetailDemoStore-eventbus\"",
   "kind": "exists",
   "select": "ssm"
  },
  {
   "id": "ssm_value",
   "tier": "core",
   "quote": "that stores the event bus name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ssm_name",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "ssm",
     "cond": {
      "path": [
       "Value"
      ],
      "op": "eq",
      "value": "retaildemostore-bus"
     }
    }
   ]
  },
  {
   "id": "export",
   "tier": "core",
   "quote": "export the event bus name under the export name \"retaildemostore-bus\"",
   "kind": "exists",
   "select": "out_exp"
  },
  {
   "id": "export_value",
   "tier": "detail",
   "quote": "we need the output to export the event bus name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "out_exp_name",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "out_exp",
     "cond": {
      "path": [
       "value"
      ],
      "op": "eq",
      "value": "retaildemostore-bus"
     }
    }
   ]
  },
  {
   "id": "events_role_trust",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "events.amazonaws.com"
   }
  },
  {
   "id": "events_role_logs",
   "tier": "extra",
   "kind": "attr",
   "select": "role",
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
  },
  {
   "id": "rule_role",
   "tier": "extra",
   "kind": "attr",
   "select": "rule_off",
   "cond": {
    "path": [
     "RoleArn"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
