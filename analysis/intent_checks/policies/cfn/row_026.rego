package intent.cfn.row_026

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
  },
  "ec2_rule": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "EventPattern"
     ],
     "op": "regex",
     "value": "aws\\.ec2"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "state_machine",
   "kind": "exists",
   "select": "sm",
   "tier": "core",
   "quote": "trigger a Step Functions state machine"
  },
  {
   "id": "rule",
   "kind": "exists",
   "select": "rule",
   "tier": "core",
   "quote": "monitor EC2 instance state changes"
  },
  {
   "id": "rule_source_ec2",
   "kind": "attr",
   "select": "rule",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "regex",
    "value": "aws\\.ec2"
   },
   "tier": "core",
   "quote": "monitor EC2 instance state changes",
   "justify": "EC2 events use source aws.ec2"
  },
  {
   "id": "rule_states",
   "kind": "all_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "rule",
     "cond": {
      "path": [
       "EventPattern"
      ],
      "op": "regex",
      "value": "(?i)running"
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
      "value": "(?i)stopped"
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
      "value": "(?i)terminated"
     }
    }
   ],
   "quote": "whenever an instance transitions to running, stopped, or terminated"
  },
  {
   "id": "rule_targets_sm",
   "kind": "ref",
   "from": "ec2_rule",
   "to": "sm",
   "tier": "core",
   "quote": "trigger a Step Functions state machine",
   "justify": "EC2 events use source aws.ec2"
  },
  {
   "id": "default_bus",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "ec2_rule",
     "cond": {
      "path": [
       "EventBusName"
      ],
      "op": "regex",
      "value": "(?i)^default$|event-bus/default$"
     }
    },
    {
     "kind": "attr",
     "select": "ec2_rule",
     "cond": {
      "path": [
       "EventBusName"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "the template should use the default event bus",
   "justify": "omitting EventBusName selects the default bus; the bus may also be given by ARN; EC2 events use source aws.ec2"
  },
  {
   "id": "sm_logging",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::StepFunctions::StateMachine"
    ],
    "where": [
     {
      "path": [
       "LoggingConfiguration",
       "Level"
      ],
      "op": "in",
      "value": [
       "ALL",
       "ERROR",
       "FATAL"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "LoggingConfiguration",
     "Destinations",
     "*",
     "CloudWatchLogsLogGroup",
     "LogGroupArn"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "include logging for the state machine",
   "justify": "a state machine logs only at level ALL, ERROR or FATAL; OFF is the default and logs nothing"
  },
  {
   "id": "log_group",
   "kind": "ref",
   "from": "sm",
   "to": "lg",
   "tier": "detail",
   "quote": "include logging for the state machine"
  },
  {
   "id": "sm_paths",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::StepFunctions::StateMachine"
      ],
      "where": [
       {
        "path": [
         "DefinitionString"
        ],
        "op": "regex",
        "value": "(?i)running"
       },
       {
        "path": [
         "DefinitionString"
        ],
        "op": "regex",
        "value": "(?i)stopped"
       },
       {
        "path": [
         "DefinitionString"
        ],
        "op": "regex",
        "value": "(?i)terminated"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::StepFunctions::StateMachine"
      ],
      "where": [
       {
        "path": [
         "Definition"
        ],
        "op": "regex",
        "value": "(?i)running"
       },
       {
        "path": [
         "Definition"
        ],
        "op": "regex",
        "value": "(?i)stopped"
       },
       {
        "path": [
         "Definition"
        ],
        "op": "regex",
        "value": "(?i)terminated"
       }
      ]
     }
    }
   ],
   "quote": "with placeholders for business logic in each path",
   "justify": "a distinct path per state is named in the prompt"
  },
  {
   "id": "x_events_role",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "tier": "extra",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "events\\.amazonaws\\.com"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
