package intent.cfn.row_005

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sm": {
   "types": [
    "AWS::StepFunctions::StateMachine"
   ],
   "where": []
  },
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
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "state_machine",
   "kind": "exists",
   "select": "sm",
   "tier": "core",
   "quote": "a serverless workflow using Step Functions"
  },
  {
   "id": "custom_event_bus",
   "kind": "exists",
   "select": "bus",
   "tier": "core",
   "quote": "a custom EventBridge event bus"
  },
  {
   "id": "workflow_puts_events",
   "kind": "attr",
   "select": "sm",
   "tier": "core",
   "quote": "sends custom events",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(events|eventbridge):putevents"
   },
   "justify": "a Step Functions workflow sending events to EventBridge uses the events:putEvents (or aws-sdk:eventbridge:putEvents) integration"
  },
  {
   "id": "workflow_targets_bus",
   "kind": "any_of",
   "tier": "detail",
   "quote": "sends custom events to a custom EventBridge event bus",
   "checks": [
    {
     "kind": "ref",
     "from": "sm",
     "to": "bus"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Role",
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "(?i)events:(putevents|\\*)"
       }
      ]
     },
     "to": "bus"
    }
   ]
  },
  {
   "id": "rule_on_bus",
   "kind": "any_of",
   "tier": "core",
   "quote": "includes a rule on that bus",
   "checks": [
    {
     "kind": "ref",
     "from": "rule",
     "to": "bus"
    },
    {
     "kind": "join",
     "from": "rule",
     "from_path": [
      "EventBusName"
     ],
     "to": "bus",
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "a CloudWatch Logs log group"
  },
  {
   "id": "rule_targets_log_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "forwards all events to a CloudWatch Logs log group",
   "checks": [
    {
     "kind": "ref",
     "from": "rule",
     "to": "lg"
    },
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "Targets",
       "*",
       "Arn"
      ],
      "op": "regex",
      "value": "(?i)arn:aws[a-z-]*:logs:.*log-group"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
