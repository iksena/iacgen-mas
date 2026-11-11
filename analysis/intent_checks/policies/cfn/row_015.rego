package intent.cfn.row_015

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
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "rp": {
   "types": [
    "AWS::Logs::ResourcePolicy"
   ],
   "where": []
  },
  "rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "rule_my_app": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "EventPattern"
     ],
     "op": "contains",
     "value": "my-application"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "event_bus",
   "kind": "exists",
   "select": "bus",
   "tier": "core",
   "quote": "a custom EventBridge event bus"
  },
  {
   "id": "bus_name",
   "kind": "attr",
   "select": "bus",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "test-bus"
   },
   "tier": "core",
   "quote": "named \"test-bus\""
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "a CloudWatch Logs log group"
  },
  {
   "id": "log_group_name",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "LogGroupName"
    ],
    "op": "eq",
    "value": "/aws/vendedlogs/events/resource-policy-test"
   },
   "tier": "core",
   "quote": "named \"/aws/vendedlogs/events/resource-policy-test\""
  },
  {
   "id": "log_resource_policy",
   "kind": "exists",
   "select": "rp",
   "tier": "core",
   "quote": "a resource policy that grants EventBridge permission"
  },
  {
   "id": "policy_events_principal",
   "kind": "attr",
   "select": "rp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "contains",
    "value": "events.amazonaws.com"
   },
   "tier": "core",
   "quote": "grants EventBridge permission"
  },
  {
   "id": "policy_create_stream",
   "kind": "attr",
   "select": "rp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "regex",
    "value": "logs:(\\*|Create\\*|CreateLog\\*|CreateLogS\\*|CreateLogStream)([^A-Za-z]|$)"
   },
   "tier": "core",
   "quote": "permission to create log streams"
  },
  {
   "id": "policy_put_events",
   "kind": "attr",
   "select": "rp",
   "cond": {
    "path": [
     "PolicyDocument"
    ],
    "op": "regex",
    "value": "logs:(\\*|Put\\*|PutLog\\*|PutLogEvents)([^A-Za-z]|$)"
   },
   "tier": "core",
   "quote": "put log events into that log group"
  },
  {
   "id": "policy_on_log_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "into that log group",
   "checks": [
    {
     "kind": "ref",
     "from": "rp",
     "to": "lg"
    },
    {
     "kind": "attr",
     "select": "rp",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "/aws/vendedlogs/events/resource-policy-test"
     }
    }
   ]
  },
  {
   "id": "rule",
   "kind": "exists",
   "select": "rule",
   "tier": "core",
   "quote": "a rule that routes events"
  },
  {
   "id": "rule_source",
   "kind": "any_of",
   "tier": "core",
   "quote": "events from the \"my-application\" source",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventPattern",
       "source",
       "*"
      ],
      "op": "eq",
      "value": "my-application"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventPattern"
      ],
      "op": "regex",
      "value": "source\\W{1,8}my-application\\W"
     }
    }
   ]
  },
  {
   "id": "rule_account",
   "kind": "any_of",
   "tier": "detail",
   "quote": "within our account",
   "justify": "\"our account\" is the stack's account, rendered as 123456789012 by the adapter; no account filter is equivalent on a custom bus with no cross-account policy",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventPattern",
       "account",
       "*"
      ],
      "op": "eq",
      "value": "123456789012"
     }
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventPattern",
       "account"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "rule_on_bus",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a custom EventBridge event bus named \"test-bus\"",
   "checks": [
    {
     "kind": "ref",
     "from": "rule",
     "to": "bus"
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventBusName"
      ],
      "op": "regex",
      "value": "(^|/)test-bus$"
     }
    }
   ]
  },
  {
   "id": "rule_targets_log_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "routes events from the \"my-application\" source within our account to the log group",
   "checks": [
    {
     "kind": "ref",
     "from": "rule_my_app",
     "to": "lg"
    },
    {
     "kind": "attr",
     "select": "rule_my_app",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Arn"
      ],
      "op": "contains",
      "value": "/aws/vendedlogs/events/resource-policy-test"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
