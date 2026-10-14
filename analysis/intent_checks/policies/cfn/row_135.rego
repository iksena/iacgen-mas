# GENERATED from specs/cfn/row_135.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_135

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "queue": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "AWS::KMS::Alias"
   ],
   "where": []
  },
  "env_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)env|stage"
    }
   ]
  },
  "decl_alarm": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::CloudWatch::Alarm"
    }
   ]
  },
  "decl_old_msg_alarm": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::CloudWatch::Alarm"
    },
    {
     "path": [
      "properties"
     ],
     "op": "contains",
     "value": "ApproximateAgeOfOldestMessage"
    }
   ]
  },
  "decl_dlq_alarm": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::CloudWatch::Alarm"
    },
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "(?i)NumberOfMessages"
    }
   ]
  },
  "decl_gated_queue": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::SQS::Queue"
    },
    {
     "path": [
      "gated"
     ],
     "op": "truthy"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "audit_queue",
   "kind": "exists",
   "select": "queue",
   "tier": "core",
   "quote": "creates an SQS queue for audit events"
  },
  {
   "id": "cmk_rotation",
   "kind": "attr",
   "select": "key",
   "tier": "core",
   "quote": "KMS encryption and key rotation",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "queue_uses_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "an SQS queue for audit events with KMS encryption",
   "checks": [
    {
     "kind": "ref",
     "from": "queue",
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "queue",
     "to": "alias"
    }
   ]
  },
  {
   "id": "alias_targets_key",
   "kind": "any_of",
   "tier": "detail",
   "quote": "KMS encryption and key rotation",
   "checks": [
    {
     "kind": "ref",
     "from": "queue",
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "alias",
     "to": "key"
    }
   ]
  },
  {
   "id": "environment_parameter",
   "kind": "exists",
   "select": "env_param",
   "tier": "detail",
   "quote": "environment-specific configuration for message retention and visibility timeout"
  },
  {
   "id": "retention_and_visibility_set",
   "kind": "all_of",
   "tier": "detail",
   "quote": "configuration for message retention and visibility timeout",
   "checks": [
    {
     "kind": "attr",
     "select": "queue",
     "cond": {
      "path": [
       "MessageRetentionPeriod"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "queue",
     "cond": {
      "path": [
       "VisibilityTimeout"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "dlq_optional_declared",
   "kind": "exists",
   "select": "decl_gated_queue",
   "tier": "core",
   "quote": "an optional dead letter queue for failed messages enabled in non-dev environments"
  },
  {
   "id": "alarm_old_messages",
   "kind": "exists",
   "select": "decl_old_msg_alarm",
   "tier": "core",
   "quote": "CloudWatch alarms to monitor for old messages"
  },
  {
   "id": "alarm_dlq_activity",
   "kind": "exists",
   "select": "decl_dlq_alarm",
   "tier": "core",
   "quote": "and DLQ activity"
  },
  {
   "id": "alarm_notifications",
   "kind": "attr",
   "select": "decl_alarm",
   "tier": "detail",
   "quote": "with SNS alerts for alarm notifications",
   "cond": {
    "path": [
     "properties",
     "AlarmActions"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
